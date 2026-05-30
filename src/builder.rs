use std::path::Path;
use std::sync::Arc;

use chrono::Local;
use regex::Regex;
use tokio::sync::Semaphore;

use serde_yaml::Value;

use crate::config::*;
use crate::convert::*;
use crate::error::*;
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
    /// Domain subscription mappings: source domain → list of proxy names
    /// Used for auto-generating proxy-providers from domain sources
    pub domain_proxies: Option<&'a std::collections::HashMap<String, Vec<String>>>,
}

// ── Main Entry Point ───────────────────────────────────────────────────────

/// Serialize a YAML section with its key for template variable substitution.
///
/// e.g. `serialize_yaml_section("proxies", &Value::Sequence(...))`
/// returns `"proxies:\n  - name: ...\n  - name: ...\n"`
fn serialize_yaml_section(key: &str, value: &Value) -> String {
    let mut map = serde_yaml::Mapping::new();
    map.insert(Value::String(key.into()), value.clone());
    serde_yaml::to_string(&Value::Mapping(map)).unwrap_or_else(|e| {
        log::error!("Failed to serialize YAML section '{}': {}", key, e);
        String::new()
    })
}

/// Substitute subconverter-style template variables (`{{...}}`) in the template text
/// with serialized YAML sections.
///
/// Supported variables:
/// - `{{proxy}}` / `{{clash_proxy_config}}` — proxy entries section
/// - `{{proxy_group}}` / `{{clash_proxy_group}}` — proxy-groups section
/// - `{{rule}}` / `{{clash_rule}}` — rules section
/// - `{{rule_provider}}` — rule-providers section
/// - `{{proxy_provider}}` / `{{clash_proxy_provider}}` — proxy-providers section
/// - `{{update}}` — current date/time string
/// - `{{custom_http}}` / `{{custom_socks5}}` — empty string placeholders
fn substitute_template_vars(
    template: &str,
    proxies_yaml: &str,
    groups_yaml: &str,
    rules_yaml: &str,
    rule_providers_yaml: Option<&str>,
    proxy_providers_yaml: Option<&str>,
) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let rp = rule_providers_yaml.unwrap_or("");
    let pp = proxy_providers_yaml.unwrap_or("");

    template
        .replace("{{proxy}}", proxies_yaml)
        .replace("{{clash_proxy_config}}", proxies_yaml)
        .replace("{{proxy_group}}", groups_yaml)
        .replace("{{clash_proxy_group}}", groups_yaml)
        .replace("{{rule}}", rules_yaml)
        .replace("{{clash_rule}}", rules_yaml)
        .replace("{{rule_provider}}", rp)
        .replace("{{proxy_provider}}", pp)
        .replace("{{clash_proxy_provider}}", pp)
        .replace("{{update}}", &now)
        .replace("{{custom_http}}", "")
        .replace("{{custom_socks5}}", "")
}

/// Build a complete Clash YAML config from enriched proxies and generation config
pub async fn build_clash_config(
    client: &reqwest::Client,
    cfg: ClashGenerationConfig<'_>,
) -> Result<String> {
    // 1. Build proxy entries
    let proxy_entries: Vec<Value> = cfg
        .enriched
        .iter()
        .map(|ep| Value::Mapping(ep.node.clash_mapping()))
        .collect();
    let all_names: Vec<String> = cfg.enriched.iter().map(|ep| ep.node.name().to_string()).collect();

    // 2. Build proxy groups
    let mut groups: Vec<Value> = Vec::new();
    let mut auto_group_names: Vec<String> = Vec::new();
    let mut custom_group_names: Vec<String> = Vec::new();

    // Smart groups (region-based) FIRST — custom groups may reference them via `[]`.
    // Custom groups use `[]` directives (e.g. `[]🇭🇰 香港 HK Auto`) to reference smart
    // auto-groups, so smart groups must be built first and their names must be known.
    if let Some(smart) = cfg.smart
        && smart.enable {
            build_smart_groups(smart, cfg.enriched, &mut groups, &mut auto_group_names, cfg.test_url);
        }

    // Custom groups (if defined) — built after smart groups so `[]` directives
    // can resolve against already-created smart group names.
    if !cfg.custom_groups.is_empty() {
        build_custom_groups(
            cfg.custom_groups,
            &all_names,
            &auto_group_names,    // known smart groups for [] validation
            cfg.enriched,
            &mut groups,
            &mut custom_group_names,
            cfg.test_url,
        );
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
    if let Some(smart) = cfg.smart
        && smart.enable && smart.generate_rules {
            let smart_rules = build_rules(smart);
            rules.extend(smart_rules);
        }

    // External rulesets (downloaded and parsed concurrently)
    let provider_threshold = cfg.template.map(|t| t.provider_threshold).unwrap_or(50);
    let ruleset_configs: Vec<RulesetConfig> = cfg.rulesets.to_vec();

    if !ruleset_configs.is_empty() {
        let sem = Arc::new(Semaphore::new(5));
        let mut rs_handles = Vec::with_capacity(ruleset_configs.len());

        for rscfg in ruleset_configs {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            rs_handles.push(tokio::spawn(async move {
                let _guard = permit;
                log::debug!("[builder] GET ruleset: {}", rscfg.url);
                let result = ruleset::fetch_and_parse_ruleset(&client, &rscfg).await;
                (rscfg, result)
            }));
        }

        for handle in rs_handles {
            match handle.await {
                Ok((rscfg, Ok(parsed))) => {
                    if parsed.large && parsed.rules.len() >= provider_threshold {
                        let pname = format!("provider_{}", rscfg.group);
                        rule_providers.push(ruleset::generate_rule_provider(
                            &pname, &rscfg.url, rscfg.interval, &parsed.behavior,
                        ));
                        rules.push(ruleset::rule_set_rule(&pname, &parsed.group));
                    } else {
                        for rule in &parsed.rules {
                            rules.push(rule.clone());
                        }
                    }
                }
                Ok((rscfg, Err(e))) => {
                    log::warn!("Failed to fetch ruleset '{}': {}", rscfg.url, e);
                }
                Err(e) => {
                    log::warn!("Ruleset task failed: {}", e);
                }
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

    // 5. Build proxy-providers section
    let proxy_providers = build_proxy_providers(&cfg);

    // ── Template Variable Substitution ────────────────────────────────────
    //
    // Strategy: serialize all sections to YAML strings first, then check if
    // the template file contains `{{...}}` variables.
    //
    // If variables are found → TEXT-LEVEL substitution path:
    //   Read template as raw text, replace each variable with serialized YAML,
    //   parse the result as YAML. Sections are embedded directly.
    //
    // If no variables found → YAML-LEVEL injection path (current behavior):
    //   Load template as YAML, strip known keys, inject sections.

    let rule_values: Vec<Value> = rules.iter().map(|r| Value::String(r.to_rule_string())).collect();

    // Serialize optional sections (only if non-empty)
    let rule_providers_yaml = if !rule_providers.is_empty() {
        let mut merged = serde_yaml::Mapping::new();
        for rp in &rule_providers {
            if let Some(map) = rp.as_mapping() {
                for (k, v) in map {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        Some(serialize_yaml_section("rule-providers", &Value::Mapping(merged)))
    } else {
        None
    };

    let proxy_providers_yaml = proxy_providers.as_ref().map(|pp| {
        serialize_yaml_section("proxy-providers", pp)
    });

    // Try substitution path (early return if successful)
    if let Some(template) = cfg.template
        && let Some(ref path) = template.base {
            let pb = Path::new(path);
            if pb.exists() {
                let template_text = std::fs::read_to_string(path)?;
                if template_text.contains("{{") {
                    // ── TEXT-LEVEL SUBSTITUTION PATH ─────────────────────
                    let proxies_yaml = serialize_yaml_section("proxies", &Value::Sequence(proxy_entries));
                    let groups_yaml = serialize_yaml_section("proxy-groups", &Value::Sequence(groups));
                    let rules_yaml = serialize_yaml_section("rules", &Value::Sequence(rule_values));

                    let substituted = substitute_template_vars(
                        &template_text,
                        &proxies_yaml,
                        &groups_yaml,
                        &rules_yaml,
                        rule_providers_yaml.as_deref(),
                        proxy_providers_yaml.as_deref(),
                    );
                    let mut base: serde_yaml::Mapping = serde_yaml::from_str(&substituted)
                        .map_err(|e| AppError::InvalidConfig(format!("Template substitution YAML: {}", e)))?;

                    // Apply config overrides
                    if let Some(ref overrides) = template.overrides {
                        for (key, val) in overrides {
                            base.insert(key.as_str().into(), toml_value_to_yaml(val));
                        }
                    }

                    return serde_yaml::to_string(&Value::Mapping(base))
                        .map_err(|e| AppError::InvalidConfig(format!("YAML serialization: {}", e)));
                }
            } else {
                log::warn!("Template file not found: {}, using default header", path);
            }
        }

    // ── NON-SUBSTITUTION PATH (current YAML-load + inject behavior) ──────
    let mut base = load_base_template(cfg.template)?;

    // Apply config overrides from template (subconverter-style config add)
    if let Some(template) = cfg.template
        && let Some(ref overrides) = template.overrides {
            for (key, val) in overrides {
                base.insert(key.as_str().into(), toml_value_to_yaml(val));
            }
        }

    // 7. Inject proxies, proxy-groups, rules, rule-providers, proxy-providers
    base.insert("proxies".into(), Value::Sequence(proxy_entries));
    base.insert("proxy-groups".into(), Value::Sequence(groups));
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

    if let Some(pp) = proxy_providers {
        base.insert("proxy-providers".into(), pp);
    }

    // 8. Serialize
    serde_yaml::to_string(&Value::Mapping(base)).map_err(|e| AppError::InvalidConfig(format!("YAML serialization: {}", e)))
}

// ── Base Template Loading ──────────────────────────────────────────────────

/// Load the base template YAML, or use the default clash template.
///
/// Legacy field names (`Proxy`, `Proxy Group`, `Rule`) are stripped — they
/// are not used by the generator. All modern field names (`proxies`,
/// `proxy-groups`, `rules`, `rule-providers`, `proxy-providers`) are
/// preserved as placeholders and will be overwritten by the generated content
/// in the caller's YAML-injection path.
fn load_base_template(template: Option<&TemplateConfig>) -> Result<serde_yaml::Mapping> {
    if let Some(t) = template
        && let Some(path) = &t.base {
            let path = Path::new(path);
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let value: Value = serde_yaml::from_str(&content)?;
                if let Some(m) = value.as_mapping() {
                    let mut base = m.clone();
                    // Strip only legacy name variants — the generator does not
                    // produce these keys, so they would pollute the output.
                    base.remove("Proxy");
                    base.remove("Proxy Group");
                    base.remove("Rule");
                    // Modern keys (proxies, proxy-groups, rules, etc.) are kept
                    // as template placeholders. The caller's `base.insert(...)`
                    // calls will overwrite them with generated content.
                    return Ok(base);
                }
                return Err(AppError::InvalidConfig("Template must be a YAML mapping".into()));
            }
            log::warn!("Template file not found: {}, using default header", path.display());
        }
    Ok(default_clash_header())
}

// ── Custom Groups ──────────────────────────────────────────────────────────

/// Parse subconverter-style `!!` directive prefixes from a proxy entry string.
/// Returns `(directive_name, pattern)` on success.
fn parse_directive(entry: &str) -> Option<(&str, &str)> {
    if let Some(v) = entry.strip_prefix("!!TYPE=") {
        Some(("TYPE", v))
    } else if let Some(v) = entry.strip_prefix("!!PORT=") {
        Some(("PORT", v))
    } else if let Some(v) = entry.strip_prefix("!!SERVER=") {
        Some(("SERVER", v))
    } else if let Some(v) = entry.strip_prefix("!!GROUP=") {
        Some(("GROUP", v))
    } else if let Some(v) = entry.strip_prefix("!!GROUPID=") {
        Some(("GROUPID", v))
    } else if let Some(v) = entry.strip_prefix("!!INSERT=") {
        Some(("GROUPID", v))
    } else {
        None
    }
}

/// Match a port `u16` against a subconverter-style range pattern.
///
/// Supported patterns (comma-separated):
/// - `443`       — exact match
/// - `1000-5000` — range (inclusive)
/// - `3000+`     — greater than or equal
/// - `500-`      — less than or equal
/// - `!443`      — negation (NOT 443)
/// - `!443,8080` — compound: NOT 443 AND NOT 8080
/// - `!1-1000`   — negated range
fn match_port_range(pattern: &str, port: u16) -> bool {
    for part in pattern.split(',') {
        let part = part.trim();
        let negate = part.starts_with('!');
        let actual = if negate { &part[1..] } else { part };
        let matches = if let Some(rest) = actual.strip_suffix('+') {
            // greater than or equal
            if let Ok(min) = rest.parse::<u16>() {
                port >= min
            } else {
                false
            }
        } else if let Some(rest) = actual.strip_suffix('-') {
            // less than or equal
            if let Ok(max) = rest.parse::<u16>() {
                port <= max
            } else {
                false
            }
        } else if actual.contains('-') {
            // range
            let parts: Vec<&str> = actual.splitn(2, '-').collect();
            if let (Ok(min), Ok(max)) =
                (parts[0].trim().parse::<u16>(), parts[1].trim().parse::<u16>())
            {
                port >= min && port <= max
            } else {
                false
            }
        } else {
            // exact
            if let Ok(n) = actual.parse::<u16>() {
                port == n
            } else {
                false
            }
        };
        if matches != negate {
            return true;
        }
    }
    false
}

/// Build user-defined proxy groups from regex patterns and `!!` directives
fn build_custom_groups(
    custom_cfgs: &[CustomGroupConfig],
    all_names: &[String],
    known_group_names: &[String],      // smart groups built before us, for [] validation
    enriched: &[EnrichedProxy],
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
                // Validate: is it a built-in policy, or does the referenced group exist?
                let is_builtin = matches!(inner, "DIRECT" | "REJECT" | "PASS");
                let is_existing_group = known_group_names.iter().any(|g| g == inner)
                    || group_names_out.iter().any(|g| g == inner);
                if is_builtin || is_existing_group {
                    members.push(inner.to_string());
                } else {
                    log::warn!(
                        "Custom group '{}': referenced group '{}' via [] does not exist. Known groups: {:?}",
                        cfg.name, inner, known_group_names
                    );
                }
            } else if let Some((directive, pattern)) = parse_directive(entry) {
                // !! directive matching against enriched proxy data
                for ep in enriched {
                    let matches = match directive {
                        "TYPE" => {
                            let type_str = match &ep.node {
                                ProxyNode::Shadowsocks(_) => "SS",
                                ProxyNode::ShadowsocksR(_) => "SSR",
                                ProxyNode::VMess(_) => "VMESS",
                                ProxyNode::Trojan(_) => "TROJAN",
                                ProxyNode::VLESS(_) => "VLESS",
                                ProxyNode::Hysteria(_) => "HYSTERIA",
                                ProxyNode::Hysteria2(_) => "HYSTERIA2",
                                ProxyNode::Tuic(_) => "TUIC",
                                ProxyNode::Snell(_) => "SNELL",
                                ProxyNode::Http(_) => "HTTP",
                                ProxyNode::Socks5(_) => "SOCKS5",
                                ProxyNode::AnyTLS(_) => "ANYTLS",
                                ProxyNode::WireGuard(_) => "WIREGUARD",
                            };
                            if let Ok(re) = Regex::new(pattern) {
                                re.is_match(type_str)
                            } else {
                                false
                            }
                        }
                        "PORT" => match_port_range(pattern, ep.node.port()),
                        "SERVER" => {
                            if let Ok(re) = Regex::new(pattern) {
                                re.is_match(ep.node.host())
                            } else {
                                false
                            }
                        }
                        "GROUP" => false, // reserved for future use
                        "GROUPID" => match_port_range(pattern, ep.source_id as u16),
                        _ => false,
                    };
                    if matches {
                        let name = ep.node.name().to_string();
                        if !members.contains(&name) {
                            members.push(name);
                        }
                    }
                }
            } else {
                // Regex pattern — match against all proxy names
                if let Ok(re) = Regex::new(entry) {
                    for name in all_names {
                        if re.is_match(name)
                            && !members.contains(name) {
                                members.push(name.clone());
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

    // Support `use:` field (proxy-provider references, subconverter-style)
    if !cfg.use_providers.is_empty() {
        let use_list: Vec<Value> = cfg.use_providers.iter().map(|n| Value::String(n.clone())).collect();
        map.insert("use".into(), Value::Sequence(use_list));
    }

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
// RegionGroup + group_by_region + build_auto_group + build_select_group
// are shared from convert via `use crate::convert::*;`

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
        groups.push(build_auto_group(&auto_name, &region.proxy_names, auto_type, test_url));
        let select_name = region.display.clone();
        groups.push(build_select_group(&select_name, &region.proxy_names));
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
        groups.push(build_auto_group(fb_name, &all_plain_names, "fallback", test_url));
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

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a `toml::Value` to a `serde_yaml::Value` for config overrides.
fn toml_value_to_yaml(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Number(serde_yaml::Number::from(*i)),
        toml::Value::Float(f) => {
            // serde_yaml::Number doesn't support f64 directly; serialize as string
            Value::String(f.to_string())
        }
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Array(arr) => {
            Value::Sequence(arr.iter().map(toml_value_to_yaml).collect())
        }
        toml::Value::Table(table) => {
            let mut map = serde_yaml::Mapping::new();
            for (k, v) in table {
                map.insert(Value::String(k.clone()), toml_value_to_yaml(v));
            }
            Value::Mapping(map)
        }
        // Datetime as string
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
    }
}

// ── Proxy Providers ────────────────────────────────────────────────────────

/// Build the `proxy-providers` section of the Clash config.
///
/// Supports:
/// 1. Explicit provider definitions from template config (subconverter-style)
/// 2. Auto-generated providers from domain subscription sources
fn build_proxy_providers(cfg: &ClashGenerationConfig<'_>) -> Option<Value> {
    let template = cfg.template?;
    let mut providers = serde_yaml::Mapping::new();

    // 1. Explicit proxy-provider definitions
    for provider in &template.proxy_providers {
        let mut entry = serde_yaml::Mapping::new();
        entry.insert("type".into(), provider.provider_type.as_str().into());

        if let Some(ref url) = provider.url {
            entry.insert("url".into(), url.as_str().into());
        }

        entry.insert("path".into(), provider.path.as_str().into());
        entry.insert("interval".into(), Value::Number(serde_yaml::Number::from(provider.interval)));

        if let Some(ref hc) = provider.health_check
            && hc.enable {
                let mut hc_map = serde_yaml::Mapping::new();
                hc_map.insert("enable".into(), true.into());
                hc_map.insert("url".into(), hc.url.as_str().into());
                hc_map.insert("interval".into(), Value::Number(serde_yaml::Number::from(hc.interval)));
                entry.insert("health-check".into(), Value::Mapping(hc_map));
            }

        providers.insert(provider.name.as_str().into(), Value::Mapping(entry));
    }

    // 2. Auto-generate providers from domain sources
    if template.auto_proxy_providers
        && let Some(domain_map) = cfg.domain_proxies {
            for (domain, proxy_names) in domain_map {
                if proxy_names.is_empty() {
                    continue;
                }
                let provider_name = format!("provider_{}", domain);
                let mut entry = serde_yaml::Mapping::new();
                entry.insert("type".into(), "http".into());
                entry.insert("interval".into(), Value::Number(serde_yaml::Number::from(86400u64)));

                let path = format!("./proxy_providers/{}.yaml", domain);
                entry.insert("path".into(), path.into());

                // Health-check for auto-generated providers
                let mut hc_map = serde_yaml::Mapping::new();
                hc_map.insert("enable".into(), true.into());
                hc_map.insert("url".into(), cfg.test_url.into());
                hc_map.insert("interval".into(), Value::Number(serde_yaml::Number::from(300u64)));
                entry.insert("health-check".into(), Value::Mapping(hc_map));

                providers.insert(provider_name.clone().into(), Value::Mapping(entry));
            }
        }

    if providers.is_empty() {
        None
    } else {
        Some(Value::Mapping(providers))
    }
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
            http_path: None,
            http_headers: None,
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
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
                use_providers: vec![],
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
                use_providers: vec![],
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

        build_custom_groups(&custom_cfgs, &names, &[], &enriched, &mut groups, &mut group_names, "https://www.gstatic.com/generate_204");

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
                use_providers: vec![],
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

        build_custom_groups(&custom_cfgs, &names, &[], &enriched, &mut groups, &mut group_names, "");

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
                use_providers: vec![],
                url: None,
                interval: 300,
                tolerance: None,
                strategy: None,
                lazy: true,
                disable_udp: false,
            },
        ];

        let enriched = vec![test_enriched("SG-01", "1.0.0.1", 443, "x", 100, "SG", "新加坡", "\u{1f1f8}\u{1f1ec}")];

        build_custom_groups(&custom_cfgs, &names, &[], &enriched, &mut groups, &mut group_names, "");

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
        // Full template should include all dynamic sections as null placeholders
        assert!(base.contains_key("proxies"), "default template must include proxies placeholder");
        assert!(base.contains_key("proxy-groups"), "default template must include proxy-groups placeholder");
        assert!(base.contains_key("rules"), "default template must include rules placeholder");
        assert!(base.contains_key("proxy-providers"), "default template must include proxy-providers placeholder");
        assert!(base.contains_key("rule-providers"), "default template must include rule-providers placeholder");
        // Placeholders must be null (will be overwritten by generated content)
        assert!(base.get("proxies").unwrap().is_null(), "proxies placeholder must be null (~)");
        assert!(base.get("proxy-groups").unwrap().is_null(), "proxy-groups placeholder must be null (~)");
        assert!(base.get("rules").unwrap().is_null(), "rules placeholder must be null (~)");
        // Meta fields must NOT be present (they're commented-out in the template)
        assert!(!base.contains_key("mixed-port"), "commented-out key mixed-port must not appear");
        assert!(!base.contains_key("ipv6"), "commented-out key ipv6 must not appear");
        assert!(!base.contains_key("tun"), "commented-out key tun must not appear");
        // DNS must be present
        assert!(base.contains_key("dns"), "default template must include dns");
    }

    #[test]
    fn test_default_clash_header_reused() {
        let header = default_clash_header();
        assert!(header.contains_key("port"));
        assert!(header.contains_key("socks-port"));
        assert!(header.contains_key("allow-lan"));
        assert!(header.contains_key("external-controller"));
        assert_eq!(
            header.get("mode").unwrap().as_str().unwrap(),
            "rule"
        );
        // Same full-template contract must hold
        assert!(header.contains_key("proxies"));
        assert!(header.contains_key("proxy-groups"));
        assert!(header.contains_key("rules"));
    }

    /// Verify that YAML injection correctly overwrites template placeholders.
    /// This simulates what `build_clash_config` does: load template, insert
    /// generated sections, verify the result is valid YAML with our content.
    #[test]
    fn test_template_placeholder_overwrite() {
        // Load default template (has null placeholders)
        let mut base = load_base_template(None).unwrap();

        // Insert generated content (simulating what build_clash_config does)
        let proxy_entries: Vec<Value> = vec![
            Value::Mapping(serde_yaml::Mapping::from_iter([
                ("name".into(), "🇺🇸 US-01".into()),
                ("type".into(), "vmess".into()),
                ("server".into(), "1.2.3.4".into()),
                ("port".into(), Value::Number(serde_yaml::Number::from(443u16))),
                ("uuid".into(), "abc-123".into()),
            ])),
        ];
        let group_entries: Vec<Value> = vec![
            Value::Mapping(serde_yaml::Mapping::from_iter([
                ("name".into(), "Proxy".into()),
                ("type".into(), "select".into()),
                ("proxies".into(), Value::Sequence(vec!["🇺🇸 US-01".into()])),
            ])),
        ];
        let rule_values: Vec<Value> = vec!["MATCH,Proxy".into()];

        base.insert("proxies".into(), Value::Sequence(proxy_entries.clone()));
        base.insert("proxy-groups".into(), Value::Sequence(group_entries.clone()));
        base.insert("rules".into(), Value::Sequence(rule_values.clone()));

        // Verify overwrite: not null anymore
        let proxies = base.get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].as_mapping().unwrap().get("name").unwrap().as_str().unwrap(), "🇺🇸 US-01");

        let groups = base.get("proxy-groups").unwrap().as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].as_mapping().unwrap().get("name").unwrap().as_str().unwrap(), "Proxy");

        let rules = base.get("rules").unwrap().as_sequence().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].as_str().unwrap(), "MATCH,Proxy");

        // Header fields must still be intact
        assert_eq!(base.get("port").unwrap().as_i64().unwrap(), 7890);
        let dns = base.get("dns").unwrap().as_mapping().unwrap();
        assert!(dns.contains_key("enable"));

        // Serialize and re-parse to verify valid YAML
        let yaml_str = serde_yaml::to_string(&Value::Mapping(base)).unwrap();
        let reparsed: serde_yaml::Value = serde_yaml::from_str(&yaml_str).unwrap();
        let map = reparsed.as_mapping().unwrap();
        assert!(map.contains_key("proxies"));
        assert!(map.contains_key("proxy-groups"));
        assert!(map.contains_key("rules"));
        assert!(map.contains_key("dns"));
        assert!(map.contains_key("experimental"));
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
                use_providers: vec![],
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

        build_custom_groups(&custom_cfgs, &names, &[], &enriched, &mut groups, &mut group_names, "");

        assert_eq!(group_names.len(), 1);
        let members = groups[0].as_mapping().unwrap().get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(members.len(), 3);
    }
}
