use std::collections::HashMap;
use std::path::Path;

use regex::Regex;

use serde_yaml::Value;

use crate::config::*;
use crate::convert::*;
use crate::error::*;
use crate::geoip;
use crate::proxy::*;
use crate::ruleset;

/// Aggregated generation config combining smart, custom, rulesets, and template
pub struct ClashGenerationConfig<'a> {
    pub enriched: &'a [EnrichedProxy],
    pub smart: Option<&'a SmartGroupConfig>,
    pub custom_groups: &'a [CustomGroupConfig],
    pub rulesets: &'a [RulesetConfig],
    pub template: Option<&'a TemplateConfig>,
    pub test_url: &'a str,
}

// ── Main Entry Point ───────────────────────────────────────────────────────

/// Build a complete Clash YAML config from enriched proxies and generation config
pub async fn build_clash_config(
    client: &reqwest::Client,
    cfg: ClashGenerationConfig<'_>,
) -> Result<String> {
    // 1. Build proxy entries
    let proxy_entries: Vec<Value> = cfg
        .enriched
        .iter()
        .filter_map(|ep| {
            let m = ep.node.clash_mapping();
            Some(Value::Mapping(m))
        })
        .collect();
    let all_names: Vec<String> = cfg.enriched.iter().map(|ep| ep.node.name().to_string()).collect();

    // 2. Build proxy groups
    let mut groups: Vec<Value> = Vec::new();
    let mut auto_group_names: Vec<String> = Vec::new();

    // Custom groups (if defined) are the primary grouping mechanism
    let mut custom_group_names: Vec<String> = Vec::new();
    if !cfg.custom_groups.is_empty() {
        build_custom_groups(cfg.custom_groups, &all_names, cfg.enriched, &mut groups, &mut custom_group_names, cfg.test_url);
    }

    // Smart groups (region-based)
    if let Some(smart) = cfg.smart {
        if smart.enable && cfg.custom_groups.is_empty() {
            // Only build smart groups when no custom groups defined
            build_smart_groups(smart, cfg.enriched, &mut groups, &mut auto_group_names, cfg.test_url);
        }
    }

    // 3. Build the main "Proxy" select group
    let main_proxy_members: Vec<String> = if !custom_group_names.is_empty() {
        // Custom groups exist — main Proxy lists them
        custom_group_names.clone()
    } else if !auto_group_names.is_empty() {
        // Smart groups — build_smart_groups already populated auto_group_names
        auto_group_names.clone()
    } else {
        // Flat mode
        all_names.clone()
    };

    // Add main Proxy group
    if !main_proxy_members.is_empty() {
        groups.push(build_select_group("Proxy", &main_proxy_members));
    }

    // 4. Build rules
    let mut rules: Vec<ClashRule> = Vec::new();
    let mut rule_providers: Vec<Value> = Vec::new();

    // Smart rules
    if let Some(smart) = cfg.smart {
        if smart.enable && smart.generate_rules {
            let smart_rules = build_rules(smart);
            rules.extend(smart_rules);
        }
    }

    // External rulesets (downloaded and parsed)
    let provider_threshold = cfg.template.map(|t| t.provider_threshold).unwrap_or(50);

    for rscfg in cfg.rulesets {
        match ruleset::fetch_and_parse_ruleset(client, rscfg).await {
            Ok(parsed) => {
                if parsed.large && parsed.rules.len() >= provider_threshold {
                    // Generate rule-provider entry + RULE-SET reference
                    let pname = format!("provider_{}", rscfg.group);
                    rule_providers.push(ruleset::generate_rule_provider(
                        &pname, &rscfg.url, rscfg.interval, &parsed.behavior,
                    ));
                    rules.push(ruleset::rule_set_rule(&pname, &parsed.group));
                } else {
                    // Inline rules
                    for rule in &parsed.rules {
                        rules.push(rule.clone());
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to fetch ruleset '{}': {}", rscfg.url, e);
            }
        }
    }

    // Custom user rules (highest priority — last pushed wins in Clash, so place them early)
    if let Some(smart) = cfg.smart {
        for rule in &smart.custom_rules {
            rules.push(ClashRule::Custom(rule.clone()));
        }
    }

    // Final MATCH rule
    rules.push(ClashRule::Match("Proxy"));

    // 5. Load or create base template
    let mut base = load_base_template(cfg.template)?;

    // 6. Inject proxies, proxy-groups, rules, rule-providers
    base.insert("proxies".into(), Value::Sequence(proxy_entries));
    base.insert("proxy-groups".into(), Value::Sequence(groups));

    let rule_values: Vec<Value> = rules.iter().map(|r| Value::String(r.to_rule_string())).collect();
    base.insert("rules".into(), Value::Sequence(rule_values));

    if !rule_providers.is_empty() {
        // Merge multiple rule-provider mappings into one
        let mut merged = serde_yaml::Mapping::new();
        for rp in &rule_providers {
            if let Some(map) = rp.as_mapping() {
                for (k, v) in map {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        base.insert("rule-providers".into(), Value::Mapping(merged));
    }

    // 7. Serialize
    serde_yaml::to_string(&Value::Mapping(base)).map_err(|e| AppError::InvalidConfig(format!("YAML serialization: {}", e)))
}

// ── Base Template Loading ──────────────────────────────────────────────────

/// Load the base template YAML, or use the default header
fn load_base_template(template: Option<&TemplateConfig>) -> Result<serde_yaml::Mapping> {
    if let Some(t) = template {
        if let Some(path) = &t.base {
            let path = Path::new(path);
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let value: Value = serde_yaml::from_str(&content)?;
                if let Some(m) = value.as_mapping() {
                    let mut base = m.clone();
                    base.remove("proxies");
                    base.remove("proxy-groups");
                    base.remove("rules");
                    base.remove("rule-providers");
                    return Ok(base);
                }
                return Err(AppError::InvalidConfig("Template must be a YAML mapping".into()));
            }
            log::warn!("Template file not found: {}, using default header", path.display());
        }
    }
    Ok(default_clash_header())
}

// ── Custom Groups ──────────────────────────────────────────────────────────

/// Build user-defined proxy groups from regex patterns
fn build_custom_groups(
    custom_cfgs: &[CustomGroupConfig],
    all_names: &[String],
    _enriched: &[EnrichedProxy],
    groups: &mut Vec<Value>,
    group_names_out: &mut Vec<String>,
    test_url: &str,
) {
    for cfg in custom_cfgs {
        let mut members: Vec<String> = Vec::new();

        for proxy_entry in &cfg.proxies {
            let entry = proxy_entry.trim();

            if entry.starts_with("[]") {
                // Special directive: []DIRECT, []REJECT, []PASS, []GroupName
                let inner = entry.trim_start_matches("[]");
                members.push(inner.to_string());
            } else {
                // Regex pattern — match against all proxy names
                if let Ok(re) = Regex::new(entry) {
                    for name in all_names {
                        if re.is_match(name) {
                            if !members.contains(name) {
                                members.push(name.clone());
                            }
                        }
                    }
                }
            }
        }

        if members.is_empty() {
            // Skip empty groups (except select groups which can reference DIRECT/REJECT)
            if !cfg.proxies.iter().any(|p| p.trim().starts_with('[')) {
                log::debug!("Custom group '{}' has no matching proxies, skipping", cfg.name);
                continue;
            }
        }

        groups.push(build_custom_group_value(cfg, &members, test_url));
        group_names_out.push(cfg.name.clone());
    }
}

/// Build a single custom proxy group YAML value
fn build_custom_group_value(cfg: &CustomGroupConfig, members: &[String], test_url: &str) -> Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), cfg.name.as_str().into());
    map.insert("type".into(), cfg.group_type.as_str().into());

    let member_list: Vec<Value> = members.iter().map(|n| Value::String(n.clone())).collect();
    map.insert("proxies".into(), Value::Sequence(member_list));

    match cfg.group_type.as_str() {
        "url-test" | "fallback" => {
            let url = cfg.url.as_deref().unwrap_or(test_url);
            map.insert("url".into(), url.into());
            map.insert("interval".into(), Value::Number(serde_yaml::Number::from(cfg.interval)));
            if let Some(tol) = cfg.tolerance {
                map.insert("tolerance".into(), Value::Number(serde_yaml::Number::from(tol)));
            }
        }
        "load-balance" => {
            if let Some(ref s) = cfg.strategy {
                map.insert("strategy".into(), s.as_str().into());
            }
            if let Some(url) = &cfg.url {
                map.insert("url".into(), url.as_str().into());
            }
        }
        _ => {} // select groups have no extra fields
    }

    if !cfg.lazy {
        map.insert("lazy".into(), false.into());
    }
    if cfg.disable_udp {
        map.insert("disable-udp".into(), true.into());
    }

    Value::Mapping(map)
}

// ── Smart Groups (region-based) ────────────────────────────────────────────

// Reuse the Structured-labeled version from convert.rs
struct RegionGroup {
    display: String,
    proxy_names: Vec<String>,
    code: String,
}

fn group_by_region(proxies: &[EnrichedProxy]) -> Vec<RegionGroup> {
    let mut regions: HashMap<String, Vec<String>> = HashMap::new();
    let mut region_emoji: HashMap<String, String> = HashMap::new();

    for ep in proxies {
        let code = if ep.country_code.is_empty() { "Unknown" } else { &ep.country_code };
        regions.entry(code.to_string()).or_default().push(ep.node.name().to_string());
        if region_emoji.get(code).is_none() && !ep.emoji.is_empty() {
            region_emoji.insert(code.to_string(), ep.emoji.clone());
        }
    }

    let mut result: Vec<RegionGroup> = regions
        .into_iter()
        .map(|(code, names)| {
            let emoji = region_emoji.get(&code).cloned().unwrap_or_default();
            let chinese_name = geoip::country_code_to_chinese(&code);
            let display = if emoji.is_empty() {
                format!("{} {}", chinese_name, code)
            } else {
                format!("{}{} {}", emoji, chinese_name, code)
            };
            RegionGroup { display, proxy_names: names, code }
        })
        .collect();

    let priority: HashMap<&str, usize> = SmartGroupConfig::regions()
        .iter()
        .enumerate()
        .map(|(i, &r)| (r, i))
        .collect();

    result.sort_by(|a, b| {
        let pa = priority.get(a.code.as_str()).copied().unwrap_or(usize::MAX);
        let pb = priority.get(b.code.as_str()).copied().unwrap_or(usize::MAX);
        pa.cmp(&pb)
    });

    result
}

fn build_smart_groups(
    smart: &SmartGroupConfig,
    enriched: &[EnrichedProxy],
    groups: &mut Vec<Value>,
    group_names_out: &mut Vec<String>,
    test_url: &str,
) {
    let regions = group_by_region(enriched);
    let auto_type = &smart.auto_group_type;

    // Per-region auto groups
    let mut region_group_names: Vec<String> = Vec::new();
    for region in &regions {
        let auto_name = format!("{} Auto", region.display);
        region_group_names.push(auto_name.clone());
        groups.push(build_auto_group_clone(&auto_name, &region.proxy_names, auto_type, test_url));
        let select_name = region.display.clone();
        groups.push(build_select_group_clone(&select_name, &region.proxy_names));
    }

    let all_yaml_names: Vec<Value> = enriched
        .iter()
        .map(|ep| Value::String(ep.node.name().to_string()))
        .collect();
    let all_plain_names: Vec<String> = enriched.iter().map(|ep| ep.node.name().to_string()).collect();

    // Load-balance group
    if smart.load_balance_group {
        let lb_name = "负载均衡 Load-Balance";
        let mut lb_map = serde_yaml::Mapping::new();
        lb_map.insert("name".into(), lb_name.into());
        lb_map.insert("type".into(), "load-balance".into());
        lb_map.insert("strategy".into(), "round-robin".into());
        lb_map.insert("proxies".into(), Value::Sequence(all_yaml_names.clone()));
        groups.push(Value::Mapping(lb_map));
        region_group_names.push(lb_name.into());
    }

    // Fallback group
    if smart.fallback_group {
        let fb_name = "故障转移 Fallback";
        groups.push(build_auto_group_clone(fb_name, &all_plain_names, "fallback", test_url));
        region_group_names.push(fb_name.into());
    }

    // Populate group_names_out with members for the caller's main Proxy group
    let main_members: Vec<String> = regions
        .iter()
        .map(|r| r.display.clone())
        .chain(region_group_names.iter().cloned())
        .collect();
    group_names_out.extend(main_members);
}

fn build_auto_group_clone(name: &str, proxies: &[String], group_type: &str, test_url: &str) -> Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), group_type.into());

    let proxy_list: Vec<Value> = proxies.iter().map(|n| Value::String(n.clone())).collect();
    map.insert("proxies".into(), Value::Sequence(proxy_list));

    if group_type == "url-test" {
        map.insert("url".into(), test_url.into());
        map.insert("interval".into(), "300".into());
        map.insert("tolerance".into(), "50".into());
    } else if group_type == "fallback" {
        map.insert("url".into(), test_url.into());
        map.insert("interval".into(), "300".into());
    }

    Value::Mapping(map)
}

fn build_select_group_clone(name: &str, proxies: &[String]) -> Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "select".into());
    let proxy_list: Vec<Value> = proxies.iter().map(|n| Value::String(n.clone())).collect();
    map.insert("proxies".into(), Value::Sequence(proxy_list));
    Value::Mapping(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vmess(name: &str, server: &str, port: u16, uuid: &str) -> ProxyNode {
        ProxyNode::VMess(VMessConfig {
            name: name.into(),
            server: server.into(),
            port,
            uuid: uuid.into(),
            alter_id: None,
            cipher: None,
            tls: None,
            skip_cert_verify: None,
            servername: None,
            network: None,
            ws_path: None,
            ws_headers: None,
            udp: None,
            packet_encoding: None,
        })
    }

    fn test_enriched(name: &str, server: &str, port: u16, uuid: &str, latency: u64, cc: &str, cn: &str, emoji: &str) -> EnrichedProxy {
        let mut ep = EnrichedProxy::new(test_vmess(name, server, port, uuid), latency);
        ep.country_code = cc.into();
        ep.country_name = cn.into();
        ep.emoji = emoji.into();
        ep
    }

    #[test]
    fn test_custom_group_regex_matching() {
        let names: Vec<String> = vec![
            "🇯🇵 JP 东京-01".to_string(),
            "🇯🇵 JP 东京-02".to_string(),
            "🇸🇬 SG 新加坡-01".to_string(),
            "🇺🇸 US 洛杉矶-01".to_string(),
            "🇭🇰 HK 香港-01".to_string(),
        ];

        let mut groups = Vec::new();
        let mut group_names = Vec::new();

        let custom_cfgs = vec![
            CustomGroupConfig {
                name: "日本节点".into(),
                group_type: "url-test".into(),
                proxies: vec!["JP|日本".into()],
                url: Some("https://www.gstatic.com/generate_204".into()),
                interval: 300,
                tolerance: Some(50),
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
            CustomGroupConfig {
                name: "DIRECT".into(),
                group_type: "select".into(),
                proxies: vec!["[]DIRECT".into()],
                url: None,
                interval: 300,
                tolerance: None,
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
        ];

        let enriched: Vec<EnrichedProxy> = names.iter().enumerate().map(|(i, n)| {
            test_enriched(n, &format!("1.0.0.{}", i+1), 443, "x", 100, "XX", "未知", "")
        }).collect();

        build_custom_groups(&custom_cfgs, &names, &enriched, &mut groups, &mut group_names, "https://www.gstatic.com/generate_204");

        assert_eq!(group_names.len(), 2);
        assert!(group_names.contains(&"日本节点".to_string()));

        // Check that 日本节点 has 2 proxies (JP matches)
        let jp_group = groups.iter().find(|g| {
            g.as_mapping().and_then(|m| m.get("name")).and_then(|n| n.as_str()) == Some("日本节点")
        }).unwrap();
        let jp_members = jp_group.as_mapping().unwrap().get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(jp_members.len(), 2);
    }

    #[test]
    fn test_empty_custom_group_skipped() {
        let names: Vec<String> = vec!["US-01".into(), "JP-01".into()];

        let mut groups = Vec::new();
        let mut group_names = Vec::new();

        let custom_cfgs = vec![
            CustomGroupConfig {
                name: "Empty Group".into(),
                group_type: "url-test".into(),
                proxies: vec!["SG|新加坡".into()],
                url: Some("https://www.gstatic.com/generate_204".into()),
                interval: 300,
                tolerance: None,
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
        ];

        let enriched: Vec<EnrichedProxy> = names.iter().map(|n| {
            test_enriched(n, "1.0.0.1", 443, "x", 100, "XX", "未知", "")
        }).collect();

        build_custom_groups(&custom_cfgs, &names, &enriched, &mut groups, &mut group_names, "");

        // Empty group with no [] directives should be skipped
        assert!(group_names.is_empty());
    }

    #[test]
    fn test_custom_group_with_direct_marker() {
        let names: Vec<String> = vec!["SG-01".into()];
        let mut groups = Vec::new();
        let mut group_names = Vec::new();

        let custom_cfgs = vec![
            CustomGroupConfig {
                name: "AdBlock".into(),
                group_type: "select".into(),
                proxies: vec!["[]REJECT".into()],
                url: None,
                interval: 300,
                tolerance: None,
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
        ];

        let enriched = vec![test_enriched("SG-01", "1.0.0.1", 443, "x", 100, "SG", "新加坡", "\u{1f1f8}\u{1f1ec}")];

        build_custom_groups(&custom_cfgs, &names, &enriched, &mut groups, &mut group_names, "");

        assert_eq!(group_names.len(), 1);
        let group = &groups[0];
        let members = group.as_mapping().unwrap().get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(members[0].as_str().unwrap(), "REJECT");
    }

    #[test]
    fn test_load_base_template_default() {
        let base = load_base_template(None).unwrap();
        assert!(base.contains_key("port"));
        assert!(base.contains_key("mode"));
    }

    #[test]
    fn test_default_clash_header_reused() {
        let header = default_clash_header();
        assert!(header.contains_key("mixed-port"));
        assert_eq!(
            header.get("mode").unwrap().as_str().unwrap(),
            "rule"
        );
    }

    #[test]
    fn test_single_custom_group_with_all_proxies() {
        let names: Vec<String> = vec!["US-01".into(), "JP-01".into(), "SG-01".into()];
        let mut groups = Vec::new();
        let mut group_names = Vec::new();

        let custom_cfgs = vec![
            CustomGroupConfig {
                name: "Proxy".into(),
                group_type: "select".into(),
                proxies: vec![".*".into()],
                url: None,
                interval: 300,
                tolerance: None,
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
        ];

        let enriched: Vec<EnrichedProxy> = names.iter().map(|n| {
            test_enriched(n, "1.0.0.1", 443, "x", 100, "XX", "未知", "")
        }).collect();

        build_custom_groups(&custom_cfgs, &names, &enriched, &mut groups, &mut group_names, "");

        assert_eq!(group_names.len(), 1);
        let members = groups[0].as_mapping().unwrap().get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(members.len(), 3);
    }
}
