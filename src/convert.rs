use std::collections::HashMap;

use serde_yaml::{Number, Value};

use crate::config::SmartGroupConfig;
use crate::error::*;
use crate::geoip;
use crate::proxy::*;

/// Clash rule variant — type-safe alternative to raw string construction.
#[derive(Debug, Clone)]
pub enum ClashRule {
    DomainSuffix(&'static str, &'static str),
    DomainKeyword(&'static str, &'static str),
    Domain(&'static str, &'static str),
    GeoIP(&'static str, &'static str),
    Match(&'static str),
    IPCIDR(&'static str, &'static str),
    IPCIDR6(&'static str, &'static str),
    SrcIPCIDR(&'static str, &'static str),
    SrcPort(&'static str, &'static str),
    DstPort(&'static str, &'static str),
    ProcessName(&'static str, &'static str),
    Custom(String),
}

impl ClashRule {
    pub fn to_rule_string(&self) -> String {
        match self {
            ClashRule::DomainSuffix(d, p) => format!("DOMAIN-SUFFIX,{},{}", d, p),
            ClashRule::DomainKeyword(k, p) => format!("DOMAIN-KEYWORD,{},{}", k, p),
            ClashRule::Domain(d, p) => format!("DOMAIN,{},{}", d, p),
            ClashRule::GeoIP(c, p) => format!("GEOIP,{},{}", c, p),
            ClashRule::Match(p) => format!("MATCH,{}", p),
            ClashRule::IPCIDR(c, p) => format!("IP-CIDR,{},{}", c, p),
            ClashRule::IPCIDR6(c, p) => format!("IP-CIDR6,{},{}", c, p),
            ClashRule::SrcIPCIDR(c, p) => format!("SRC-IP-CIDR,{},{}", c, p),
            ClashRule::SrcPort(p, pol) => format!("SRC-PORT,{},{}", p, pol),
            ClashRule::DstPort(p, pol) => format!("DST-PORT,{},{}", p, pol),
            ClashRule::ProcessName(n, p) => format!("PROCESS-NAME,{},{}", n, p),
            ClashRule::Custom(s) => s.clone(),
        }
    }
}

/// Default health-check URL used throughout the Clash config generation.
const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Top-level Clash config header keys shared by all output modes.
/// Aligned with subconverter's standard (GeneralClashConfig.yml / simple_base.yml).
pub(crate) fn default_clash_header() -> serde_yaml::Mapping {
    let yaml_str = include_str!("../base/clash_default.yml");
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml_str).expect("Built-in Clash template base/clash_default.yml is invalid");
    value
        .as_mapping()
        .expect("Built-in Clash template base/clash_default.yml must be a mapping")
        .clone()
}

// ── Build Single Proxy Entry ────────────────────────────────────────────────

fn build_clash_entry(node: &ProxyNode) -> Option<serde_yaml::Value> {
    Some(serde_yaml::Value::Mapping(node.clash_mapping()))
}

// ── Group By Region ─────────────────────────────────────────────────────────

pub(crate) struct RegionGroup {
    pub(crate) display: String,
    pub(crate) proxy_names: Vec<String>,
    pub(crate) code: String,
}

pub(crate) fn group_by_region(proxies: &[EnrichedProxy]) -> Vec<RegionGroup> {
    let mut regions: HashMap<String, Vec<String>> = HashMap::new();
    let mut region_emoji: HashMap<String, String> = HashMap::new();

    for ep in proxies {
        let code = if ep.country_code.is_empty() { "Unknown" } else { &ep.country_code };
        regions.entry(code.to_string()).or_default().push(ep.node.name().to_string());
        if !region_emoji.contains_key(code) && !ep.emoji.is_empty() {
            region_emoji.insert(code.to_string(), ep.emoji.clone());
        }
    }

    let mut result: Vec<RegionGroup> = regions
        .into_iter()
        .map(|(code, names)| {
            let emoji = region_emoji.get(&code).cloned().unwrap_or_default();
            let chinese_name = geoip::country_code_to_chinese(&code);
            let display = if code == "Unknown" {
                // Avoid "Unknown Unknown" — use a cleaner fallback name
                if emoji.is_empty() { "其他 Other".into() } else { format!("{} 其他 Other", emoji) }
            } else if emoji.is_empty() {
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

// ── Build Proxy Group ───────────────────────────────────────────────────────

pub(crate) fn build_auto_group(name: &str, proxies: &[String], group_type: &str, test_url: &str) -> serde_yaml::Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), group_type.into());

    let proxy_list: Vec<serde_yaml::Value> = proxies
        .iter()
        .map(|n| serde_yaml::Value::String(n.clone()))
        .collect();
    map.insert("proxies".into(), serde_yaml::Value::Sequence(proxy_list));

    if group_type == "url-test" {
        map.insert("url".into(), test_url.into());
        map.insert("interval".into(), Value::Number(Number::from(300u64)));
        map.insert("tolerance".into(), Value::Number(Number::from(50u64)));
    } else if group_type == "fallback" {
        map.insert("url".into(), test_url.into());
        map.insert("interval".into(), Value::Number(Number::from(300u64)));
    }

    serde_yaml::Value::Mapping(map)
}

pub(crate) fn build_select_group(name: &str, proxies: &[String]) -> serde_yaml::Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "select".into());
    let proxy_list: Vec<serde_yaml::Value> = proxies
        .iter()
        .map(|n| serde_yaml::Value::String(n.clone()))
        .collect();
    map.insert("proxies".into(), serde_yaml::Value::Sequence(proxy_list));
    serde_yaml::Value::Mapping(map)
}

// ── Build Rules ─────────────────────────────────────────────────────────────

pub(crate) fn build_rules(smart: &SmartGroupConfig) -> Vec<ClashRule> {
    let mut rules = Vec::new();

    if smart.ai_rules {
        rules.extend([
            ClashRule::DomainSuffix("chatgpt.com", "Proxy"),
            ClashRule::DomainSuffix("openai.com", "Proxy"),
            ClashRule::DomainSuffix("claude.ai", "Proxy"),
            ClashRule::DomainSuffix("anthropic.com", "Proxy"),
            ClashRule::DomainSuffix("gemini.google.com", "Proxy"),
            ClashRule::DomainSuffix("copilot.microsoft.com", "Proxy"),
            ClashRule::DomainSuffix("perplexity.ai", "Proxy"),
            ClashRule::DomainSuffix("deepseek.com", "Proxy"),
            ClashRule::DomainSuffix("ai.com", "Proxy"),
            ClashRule::DomainSuffix("grok.com", "Proxy"),
            ClashRule::DomainSuffix("x.ai", "Proxy"),
            ClashRule::DomainSuffix("mistral.ai", "Proxy"),
            ClashRule::DomainSuffix("cohere.ai", "Proxy"),
            ClashRule::DomainSuffix("huggingface.co", "Proxy"),
            ClashRule::DomainSuffix("githubcopilot.com", "Proxy"),
            ClashRule::DomainKeyword("aistudio", "Proxy"),
            ClashRule::DomainKeyword("openai", "Proxy"),
        ]);
    }

    if smart.streaming_rules {
        rules.extend([
            ClashRule::DomainSuffix("netflix.com", "Proxy"),
            ClashRule::DomainSuffix("nflxvideo.net", "Proxy"),
            ClashRule::DomainSuffix("netflix.net", "Proxy"),
            ClashRule::DomainSuffix("disneyplus.com", "Proxy"),
            ClashRule::DomainSuffix("hbomax.com", "Proxy"),
            ClashRule::DomainSuffix("max.com", "Proxy"),
            ClashRule::DomainSuffix("primevideo.com", "Proxy"),
            ClashRule::DomainSuffix("youtube.com", "Proxy"),
            ClashRule::DomainSuffix("googlevideo.com", "Proxy"),
            ClashRule::DomainSuffix("ytimg.com", "Proxy"),
            ClashRule::DomainSuffix("spotify.com", "Proxy"),
            ClashRule::DomainSuffix("applemusic.com", "Proxy"),
            ClashRule::DomainSuffix("tv.apple.com", "Proxy"),
            ClashRule::DomainSuffix("hulu.com", "Proxy"),
            ClashRule::DomainSuffix("peacocktv.com", "Proxy"),
            ClashRule::DomainSuffix("paramountplus.com", "Proxy"),
            ClashRule::DomainSuffix("cbs.com", "Proxy"),
            ClashRule::DomainSuffix("hbo.com", "Proxy"),
            ClashRule::DomainSuffix("nowtv.com", "Proxy"),
            ClashRule::DomainSuffix("bbc.co.uk", "Proxy"),
            ClashRule::DomainSuffix("bbc.com", "Proxy"),
            ClashRule::DomainSuffix("iplayer.com", "Proxy"),
            ClashRule::DomainSuffix("crunchyroll.com", "Proxy"),
            ClashRule::DomainSuffix("funimation.com", "Proxy"),
            ClashRule::DomainSuffix("bilibili.com", "Proxy"),
            ClashRule::DomainSuffix("tver.jp", "Proxy"),
            ClashRule::DomainSuffix("abema.tv", "Proxy"),
            ClashRule::DomainSuffix("dmm.co.jp", "Proxy"),
            ClashRule::DomainSuffix("nicovideo.jp", "Proxy"),
            ClashRule::DomainSuffix("shahid.net", "Proxy"),
            ClashRule::DomainSuffix("hotstar.com", "Proxy"),
            ClashRule::DomainSuffix("iqiyi.com", "Proxy"),
            ClashRule::DomainSuffix("viki.com", "Proxy"),
            ClashRule::DomainSuffix("dailymotion.com", "Proxy"),
            ClashRule::DomainSuffix("tubi.tv", "Proxy"),
            ClashRule::DomainSuffix("pluto.tv", "Proxy"),
            ClashRule::DomainSuffix("pbs.org", "Proxy"),
            ClashRule::DomainSuffix("twitch.tv", "Proxy"),
            ClashRule::DomainSuffix("vimeo.com", "Proxy"),
            ClashRule::DomainKeyword("speedtest", "Proxy"),
        ]);
    }

    if smart.social_rules {
        rules.extend([
            ClashRule::DomainSuffix("twitter.com", "Proxy"),
            ClashRule::DomainSuffix("x.com", "Proxy"),
            ClashRule::DomainSuffix("t.co", "Proxy"),
            ClashRule::DomainSuffix("instagram.com", "Proxy"),
            ClashRule::DomainSuffix("tiktok.com", "Proxy"),
            ClashRule::DomainSuffix("facebook.com", "Proxy"),
            ClashRule::DomainSuffix("fbcdn.net", "Proxy"),
            ClashRule::DomainSuffix("messenger.com", "Proxy"),
            ClashRule::DomainSuffix("telegram.org", "Proxy"),
            ClashRule::DomainSuffix("tdesktop.com", "Proxy"),
            ClashRule::DomainSuffix("whatsapp.net", "Proxy"),
            ClashRule::DomainSuffix("signal.org", "Proxy"),
            ClashRule::DomainSuffix("slack.com", "Proxy"),
            ClashRule::DomainSuffix("discord.com", "Proxy"),
            ClashRule::DomainSuffix("discordapp.net", "Proxy"),
            ClashRule::DomainSuffix("discord.gg", "Proxy"),
            ClashRule::DomainSuffix("reddit.com", "Proxy"),
            ClashRule::DomainSuffix("pinterest.com", "Proxy"),
            ClashRule::DomainSuffix("quora.com", "Proxy"),
            ClashRule::DomainSuffix("medium.com", "Proxy"),
            ClashRule::DomainSuffix("tumblr.com", "Proxy"),
            ClashRule::DomainSuffix("snapchat.com", "Proxy"),
            ClashRule::DomainSuffix("linkedin.com", "Proxy"),
            ClashRule::DomainSuffix("threads.net", "Proxy"),
            ClashRule::DomainSuffix("mastodon.social", "Proxy"),
            ClashRule::DomainSuffix("bsky.app", "Proxy"),
            ClashRule::DomainSuffix("telegram.me", "Proxy"),
            ClashRule::DomainSuffix("t.me", "Proxy"),
            ClashRule::DomainSuffix("nitter.net", "Proxy"),
        ]);
    }

    if smart.gaming_rules {
        rules.extend([
            ClashRule::DomainSuffix("steampowered.com", "Proxy"),
            ClashRule::DomainSuffix("steamcommunity.com", "Proxy"),
            ClashRule::DomainSuffix("steamstore.com", "Proxy"),
            ClashRule::DomainSuffix("epicgames.com", "Proxy"),
            ClashRule::DomainSuffix("xbox.com", "Proxy"),
            ClashRule::DomainSuffix("playstation.com", "Proxy"),
            ClashRule::DomainSuffix("nintendo.com", "Proxy"),
            ClashRule::DomainSuffix("origin.com", "Proxy"),
            ClashRule::DomainSuffix("ea.com", "Proxy"),
            ClashRule::DomainSuffix("riotgames.com", "Proxy"),
            ClashRule::DomainSuffix("battle.net", "Proxy"),
            ClashRule::DomainSuffix("blizzard.com", "Proxy"),
            ClashRule::DomainSuffix("ubisoft.com", "Proxy"),
            ClashRule::DomainSuffix("rockstargames.com", "Proxy"),
        ]);
    }

    if smart.banking_rules {
        rules.extend([
            ClashRule::DomainSuffix("icbc.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("cmbchina.com", "DIRECT"),
            ClashRule::DomainSuffix("ccb.com", "DIRECT"),
            ClashRule::DomainSuffix("abchina.com", "DIRECT"),
            ClashRule::DomainSuffix("boc.cn", "DIRECT"),
            ClashRule::DomainSuffix("bankofchina.com", "DIRECT"),
            ClashRule::DomainSuffix("spdb.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("cgbchina.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("cib.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("hxb.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("cebbank.com", "DIRECT"),
            ClashRule::DomainSuffix("pbccrc.org.cn", "DIRECT"),
        ]);
    }

    if smart.direct_rules {
        rules.extend([
            ClashRule::DomainSuffix("cn", "DIRECT"),
            ClashRule::DomainSuffix("baidu.com", "DIRECT"),
            ClashRule::DomainSuffix("baidustatic.com", "DIRECT"),
            ClashRule::DomainSuffix("bdstatic.com", "DIRECT"),
            ClashRule::DomainSuffix("aliyun.com", "DIRECT"),
            ClashRule::DomainSuffix("taobao.com", "DIRECT"),
            ClashRule::DomainSuffix("tmall.com", "DIRECT"),
            ClashRule::DomainSuffix("jd.com", "DIRECT"),
            ClashRule::DomainSuffix("qq.com", "DIRECT"),
            ClashRule::DomainSuffix("tencent.com", "DIRECT"),
            ClashRule::DomainSuffix("weixin.com", "DIRECT"),
            ClashRule::DomainSuffix("wechat.com", "DIRECT"),
            ClashRule::DomainSuffix("163.com", "DIRECT"),
            ClashRule::DomainSuffix("126.com", "DIRECT"),
            ClashRule::DomainSuffix("sina.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("sinaimg.cn", "DIRECT"),
            ClashRule::DomainSuffix("sohu.com", "DIRECT"),
            ClashRule::DomainSuffix("huanqiu.com", "DIRECT"),
            ClashRule::DomainSuffix("xinhuanet.com", "DIRECT"),
            ClashRule::DomainSuffix("people.com.cn", "DIRECT"),
            ClashRule::DomainSuffix("gov.cn", "DIRECT"),
            ClashRule::DomainSuffix("edu.cn", "DIRECT"),
            ClashRule::DomainSuffix("12306.cn", "DIRECT"),
            ClashRule::DomainSuffix("ctrip.com", "DIRECT"),
            ClashRule::DomainSuffix("douyin.com", "DIRECT"),
            ClashRule::DomainSuffix("zhihu.com", "DIRECT"),
            ClashRule::DomainSuffix("meituan.com", "DIRECT"),
            ClashRule::DomainSuffix("dianping.com", "DIRECT"),
            ClashRule::DomainSuffix("douban.com", "DIRECT"),
            ClashRule::GeoIP("CN", "DIRECT"),
        ]);
    }

    // Custom user rules — highest priority
    for rule in &smart.custom_rules {
        rules.push(ClashRule::Custom(rule.clone()));
    }

    rules
}

// ── Main Conversion Entry Points ────────────────────────────────────────────

/// Legacy: basic flat output (no smart grouping). Used when smart config is disabled.
pub fn convert_proxies_to_clash(nodes: &[ProxyNode]) -> Result<String> {
    let entries: Vec<serde_yaml::Value> = nodes.iter().filter_map(build_clash_entry).collect();
    let proxy_names: Vec<String> = nodes.iter().map(|n| n.name().to_string()).collect();

    let name_list: Vec<serde_yaml::Value> = proxy_names
        .iter()
        .map(|n| serde_yaml::Value::String(n.clone()))
        .collect();

    let group = serde_yaml::Mapping::from_iter([
        ("name".into(), "Proxy".into()),
        ("type".into(), "select".into()),
        ("proxies".into(), serde_yaml::Value::Sequence(name_list)),
    ]);

    let mut config = default_clash_header();
    config.insert("proxies".into(), serde_yaml::Value::Sequence(entries));
    config.insert(
        "proxy-groups".into(),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(group)]),
    );
    config.insert(
        "rules".into(),
        serde_yaml::Value::Sequence(vec![ClashRule::Match("Proxy").to_rule_string().into()]),
    );

    serde_yaml::to_string(&serde_yaml::Value::Mapping(config)).map_err(Into::into)
}

/// Smart conversion: enriched proxies with latency, geo-aware groups, and rule generation.
pub fn convert_enriched_to_clash(
    proxies: &[EnrichedProxy],
    smart_cfg: Option<&SmartGroupConfig>,
) -> Result<String> {
    let entries: Vec<serde_yaml::Value> = proxies.iter().filter_map(|ep| build_clash_entry(&ep.node)).collect();
    let all_names: Vec<String> = proxies.iter().map(|ep| ep.node.name().to_string()).collect();
    let all_yaml_names: Vec<serde_yaml::Value> = all_names.iter().map(|n| serde_yaml::Value::String(n.clone())).collect();

    let mut config = default_clash_header();
    config.insert("proxies".into(), serde_yaml::Value::Sequence(entries));

    // ── Build Proxy Groups ──────────────────────────────────────────────
    let mut groups: Vec<serde_yaml::Value> = Vec::new();

    if let Some(smart) = smart_cfg {
        if smart.enable {
            let regions = group_by_region(proxies);
            let auto_type = &smart.auto_group_type;

            // Per-region auto groups
            let mut region_group_names: Vec<String> = Vec::new();
            for region in &regions {
                let auto_name = format!("{} Auto", region.display);
                region_group_names.push(auto_name.clone());
                groups.push(build_auto_group(&auto_name, &region.proxy_names, auto_type, DEFAULT_TEST_URL));

                // Also add a select group for manual picking within the region
                let select_name = region.display.clone();
                groups.push(build_select_group(&select_name, &region.proxy_names));
            }

            // Global load-balance group
            if smart.load_balance_group {
                let lb_name = "负载均衡 Load-Balance";
                let mut lb_map = serde_yaml::Mapping::new();
                lb_map.insert("name".into(), lb_name.into());
                lb_map.insert("type".into(), "load-balance".into());
                lb_map.insert("strategy".into(), "round-robin".into());
                lb_map.insert("proxies".into(), serde_yaml::Value::Sequence(all_yaml_names.clone()));
                groups.push(serde_yaml::Value::Mapping(lb_map));
                region_group_names.push(lb_name.into());
            }

            // Global fallback group
            if smart.fallback_group {
                let fb_name = "故障转移 Fallback";
                // Fallback points to region auto groups + all proxies sorted by latency
                let fb_proxies: Vec<String> = proxies.iter()
                    .map(|ep| ep.node.name().to_string())
                    .collect();
                groups.push(build_auto_group(fb_name, &fb_proxies, "fallback", DEFAULT_TEST_URL));
                region_group_names.push(fb_name.into());
            }

            // Main Proxy select group — lists region select groups + special groups
            let main_proxies: Vec<String> = regions.iter()
                .map(|r| r.display.clone())           // region select groups
                .chain(region_group_names.iter().cloned()) // auto/fallback/lb groups
                .collect();
            groups.push(build_select_group("Proxy", &main_proxies));

            // ── Build Rules ─────────────────────────────────────────────
            let mut rules = build_rules(smart);
            rules.push(ClashRule::Match("Proxy"));
            let rule_values: Vec<serde_yaml::Value> = rules.iter()
                .map(|r| serde_yaml::Value::String(r.to_rule_string()))
                .collect();
            config.insert("rules".into(), serde_yaml::Value::Sequence(rule_values));
        } else {
            // Smart disabled — fall back to legacy behavior
            groups.push(build_select_group("Proxy", &all_names));
            config.insert(
                "rules".into(),
                serde_yaml::Value::Sequence(vec!["MATCH,Proxy".into()]),
            );
        }
    } else {
        // No smart config — legacy behavior
        groups.push(build_select_group("Proxy", &all_names));
        config.insert(
            "rules".into(),
            serde_yaml::Value::Sequence(vec!["MATCH,Proxy".into()]),
        );
    }

    config.insert("proxy-groups".into(), serde_yaml::Value::Sequence(groups));

    serde_yaml::to_string(&serde_yaml::Value::Mapping(config)).map_err(Into::into)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmartGroupConfig;

    // ── Test helpers ──────────────────────────────────────────────────────────

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
        let country = cc.to_string();
        let mut ep = EnrichedProxy::new(
            test_vmess(name, server, port, uuid),
            latency,
        );
        ep.country_code = country;
        ep.country_name = cn.into();
        ep.emoji = emoji.into();
        ep
    }

    fn parse_clash_yaml(yaml: &str) -> serde_yaml::Mapping {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value.as_mapping().expect("top level should be mapping").clone()
    }

    fn ck(s: &str) -> serde_yaml::Value {
        serde_yaml::Value::String(s.to_string())
    }

    #[test]
    fn test_legacy_conversion() {
        let node = ProxyNode::VMess(VMessConfig {
            name: "test-node".into(),
            server: "1.2.3.4".into(),
            port: 443,
            uuid: "abc-123".into(),
            alter_id: Some("0".into()),
            cipher: Some("auto".into()),
            tls: Some(true),
            skip_cert_verify: Some(true),
            servername: Some("example.com".into()),
            network: Some("ws".into()),
            ws_path: Some("/ws".into()),
            ws_headers: None,
            udp: None,
            packet_encoding: None,
            http_path: None,
            http_headers: None,
            h2_path: None,
            h2_host: None,
            grpc_service_name: None,
        });

        let mapping = parse_clash_yaml(&convert_proxies_to_clash(&[node]).unwrap());

        assert!(mapping.contains_key(ck("proxies")));
        assert!(mapping.contains_key(ck("proxy-groups")));
        assert!(mapping.contains_key(ck("rules")));

        let proxies = mapping.get(ck("proxies")).unwrap().as_sequence().unwrap();
        assert_eq!(proxies.len(), 1);
        let proxy = proxies[0].as_mapping().unwrap();
        assert_eq!(proxy.get(ck("name")).unwrap().as_str().unwrap(), "test-node");

        let groups = mapping.get(ck("proxy-groups")).unwrap().as_sequence().unwrap();
        assert_eq!(groups.len(), 1);
        let group = groups[0].as_mapping().unwrap();
        assert_eq!(group.get(ck("name")).unwrap().as_str().unwrap(), "Proxy");
        assert_eq!(group.get(ck("type")).unwrap().as_str().unwrap(), "select");

        let rules = mapping.get(ck("rules")).unwrap().as_sequence().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].as_str().unwrap(), "MATCH,Proxy");
    }

    #[test]
    fn test_smart_conversion_generates_groups() {
        let ep1 = test_enriched("tokyo-01", "1.0.0.1", 443, "a", 120, "JP", "日本", "\u{1f1ef}\u{1f1f5}");
        let ep2 = test_enriched("sing-01", "2.0.0.1", 443, "b", 80, "SG", "新加坡", "\u{1f1f8}\u{1f1ec}");

        let smart = SmartGroupConfig {
            enable: true,
            region_groups: true,
            auto_group_type: "url-test".into(),
            fallback_group: true,
            load_balance_group: true,
            generate_rules: true,
            ai_rules: true,
            streaming_rules: true,
            social_rules: true,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: true,
            custom_rules: vec![],
        };

        let mapping = parse_clash_yaml(&convert_enriched_to_clash(&[ep1, ep2], Some(&smart)).unwrap());

        let groups = mapping.get(ck("proxy-groups")).unwrap().as_sequence().unwrap();
        // Groups: JP Auto, JP select, SG Auto, SG select, LB, Fallback, Proxy = 7
        assert!(groups.len() >= 6, "expected at least 6 groups, got {}", groups.len());

        let group_names: Vec<&str> = groups
            .iter()
            .filter_map(|g| g.as_mapping()?.get(ck("name"))?.as_str())
            .collect();
        assert!(group_names.iter().any(|n| n.contains("日本")));
        assert!(group_names.iter().any(|n| n.contains("新加坡")));
        assert!(group_names.iter().any(|n| n.contains("Auto")));
        assert!(group_names.iter().any(|n| n.contains("Fallback")));

        let rules = mapping.get(ck("rules")).unwrap().as_sequence().unwrap();
        let rule_strs: Vec<&str> = rules.iter().filter_map(|r| r.as_str()).collect();
        assert!(rule_strs.iter().any(|r| r.contains("chatgpt")));
        assert!(rule_strs.iter().any(|r| r.contains("GEOIP,CN,DIRECT")));
        assert!(rule_strs.iter().any(|r| r.contains("MATCH,Proxy")));
    }

    // ── ClashRule enum tests ──────────────────────────────────────────────────

    #[test]
    fn test_clash_rule_to_string() {
        assert_eq!(ClashRule::DomainSuffix("example.com", "Proxy").to_rule_string(), "DOMAIN-SUFFIX,example.com,Proxy");
        assert_eq!(ClashRule::DomainKeyword("google", "Proxy").to_rule_string(), "DOMAIN-KEYWORD,google,Proxy");
        assert_eq!(ClashRule::Domain("example.com", "Proxy").to_rule_string(), "DOMAIN,example.com,Proxy");
        assert_eq!(ClashRule::GeoIP("CN", "DIRECT").to_rule_string(), "GEOIP,CN,DIRECT");
        assert_eq!(ClashRule::Match("Proxy").to_rule_string(), "MATCH,Proxy");
        assert_eq!(ClashRule::IPCIDR("1.2.3.4/32", "Proxy").to_rule_string(), "IP-CIDR,1.2.3.4/32,Proxy");
        assert_eq!(ClashRule::IPCIDR6("::1/128", "Proxy").to_rule_string(), "IP-CIDR6,::1/128,Proxy");
        assert_eq!(ClashRule::SrcIPCIDR("10.0.0.0/8", "DIRECT").to_rule_string(), "SRC-IP-CIDR,10.0.0.0/8,DIRECT");
        assert_eq!(ClashRule::SrcPort("1234", "Proxy").to_rule_string(), "SRC-PORT,1234,Proxy");
        assert_eq!(ClashRule::DstPort("80", "DIRECT").to_rule_string(), "DST-PORT,80,DIRECT");
        assert_eq!(ClashRule::ProcessName("chrome", "Proxy").to_rule_string(), "PROCESS-NAME,chrome,Proxy");
        assert_eq!(ClashRule::Custom("DOMAIN-SUFFIX,test.org,Proxy".into()).to_rule_string(), "DOMAIN-SUFFIX,test.org,Proxy");
    }

    // ── Edge case: empty input ────────────────────────────────────────────────

    #[test]
    fn test_legacy_empty_input() {
        let yaml = convert_proxies_to_clash(&[]).unwrap();
        let mapping = parse_clash_yaml(&yaml);
        let proxies = mapping.get(ck("proxies")).unwrap().as_sequence().unwrap();
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_smart_empty_input() {
        let smart = SmartGroupConfig {
            enable: true,
            region_groups: true,
            auto_group_type: "url-test".into(),
            fallback_group: true,
            load_balance_group: true,
            generate_rules: true,
            ai_rules: true,
            streaming_rules: true,
            social_rules: true,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: true,
            custom_rules: vec![],
        };
        let yaml = convert_enriched_to_clash(&[], Some(&smart)).unwrap();
        let mapping = parse_clash_yaml(&yaml);
        // Should still produce valid YAML with empty proxies
        let proxies = mapping.get(ck("proxies")).unwrap().as_sequence().unwrap();
        assert!(proxies.is_empty());
        // Groups should still be generated (at least Proxy)
        let groups = mapping.get(ck("proxy-groups")).unwrap().as_sequence().unwrap();
        assert!(!groups.is_empty());
    }

    // ── default_clash_header verification ─────────────────────────────────────

    #[test]
    fn test_default_clash_header_contains_expected_keys() {
        let header = default_clash_header();
        // Core fields (subconverter standard: simple_base.yml / all_base.tpl)
        assert!(header.contains_key(ck("port")));
        assert!(header.contains_key(ck("socks-port")));
        assert!(header.contains_key(ck("allow-lan")));
        assert!(header.contains_key(ck("mode")));
        assert!(header.contains_key(ck("log-level")));
        assert!(header.contains_key(ck("external-controller")));
        // Enhanced default includes DNS and experimental sections
        assert!(
            header.contains_key(ck("dns")),
            "default_clash_header should include dns section"
        );
        assert!(
            header.contains_key(ck("experimental")),
            "default_clash_header should include experimental section"
        );
        // Meta-specific fields should still be absent from the standard default
        assert!(!header.contains_key(ck("mixed-port")));
        assert!(!header.contains_key(ck("ipv6")));
        assert!(!header.contains_key(ck("unified-delay")));
        assert!(!header.contains_key(ck("tcp-concurrent")));
        assert!(!header.contains_key(ck("connectivity-check")));
        assert!(!header.contains_key(ck("global-client-fingerprint")));
        assert!(!header.contains_key(ck("find-process-mode")));
        assert!(!header.contains_key(ck("geo-auto-update")));
        // Values
        assert_eq!(header.get(ck("port")).unwrap().as_i64().unwrap(), 7890);
        assert_eq!(header.get(ck("socks-port")).unwrap().as_i64().unwrap(), 7891);
        assert!(header.get(ck("allow-lan")).unwrap().as_bool().unwrap());
        assert_eq!(header.get(ck("mode")).unwrap().as_str().unwrap(), "rule");
        assert_eq!(header.get(ck("log-level")).unwrap().as_str().unwrap(), "info");
    }

    // ── Round-trip: all proxy types through legacy conversion ─────────────────

    fn make_ss() -> ProxyNode {
        ProxyNode::Shadowsocks(ShadowsocksConfig {
            name: "ss-test".into(), server: "10.0.0.1".into(), port: 8388,
            cipher: "chacha20-ietf-poly1305".into(),
            password: Some("sekret".into()), plugin: None, plugin_opts: None, udp: None,
        })
    }

    fn make_ssr() -> ProxyNode {
        ProxyNode::ShadowsocksR(ShadowsocksRConfig {
            name: "ssr-test".into(), server: "10.0.0.2".into(), port: 8389,
            password: Some("sekret".into()), cipher: "aes-256-cfb".into(),
            obfs: "tls1.2_ticket_auth".into(), obfs_param: "".into(),
            protocol: "auth_aes128_md5".into(), protocol_param: "".into(),
            udp: None,
        })
    }

    fn make_trojan() -> ProxyNode {
        ProxyNode::Trojan(TrojanConfig {
            name: "trojan-test".into(), server: "10.0.0.3".into(), port: 443,
            password: "pass123".into(), sni: Some("trojan.example.com".into()),
            alpn: Some(vec!["h2".into(), "http/1.1".into()]),
            skip_cert_verify: Some(true), udp: Some(true),
            network: None, ws_path: None, ws_headers: None, grpc_service_name: None,
        })
    }

    fn make_vless() -> ProxyNode {
        ProxyNode::VLESS(VLESSConfig {
            name: "vless-test".into(), server: "10.0.0.4".into(), port: 443,
            uuid: "uuid-vless".into(), tls: Some(true),
            skip_cert_verify: Some(false), servername: Some("vless.example.com".into()),
            network: Some("ws".into()), ws_path: Some("/vless".into()),
            ws_headers: None, flow: Some("xtls-rprx-vision".into()),
            packet_encoding: None,
        })
    }

    fn make_hysteria2() -> ProxyNode {
        ProxyNode::Hysteria2(Hysteria2Config {
            name: "hy2-test".into(), server: "10.0.0.5".into(), port: 443,
            password: "hy2-pass".into(), sni: Some("hy2.example.com".into()),
            skip_cert_verify: Some(true), alpn: Some(vec!["h3".into()]),
            obfs: Some("salamander".into()), obfs_password: Some("obfs-pass".into()),
            ports: None, up: None, down: None, ca: None, ca_str: None, cwnd: None, hop_interval: None,
        })
    }

    fn make_tuic() -> ProxyNode {
        ProxyNode::Tuic(TuicConfig {
            name: "tuic-test".into(), server: "10.0.0.6".into(), port: 443,
            token: "tuic-token".into(), ip: Some("10.0.0.6".into()),
            sni: Some("tuic.example.com".into()),
            skip_cert_verify: Some(true),
            alpn: Some(vec!["h3".into()]),
            udp_relay_mode: Some("quic".into()),
            congestion_controller: Some("bbr".into()),
        })
    }

    fn make_snell() -> ProxyNode {
        ProxyNode::Snell(SnellConfig {
            name: "snell-test".into(), server: "10.0.0.7".into(), port: 4567,
            psk: "snell-psk".into(), obfs: Some("http".into()), version: Some(4),
        })
    }

    fn make_http() -> ProxyNode {
        ProxyNode::Http(HttpConfig {
            name: "http-test".into(), server: "10.0.0.8".into(), port: 3128,
            username: "user".into(), password: Some("pass".into()),
            tls: Some(true), sni: Some("http.example.com".into()),
            skip_cert_verify: Some(false),
        })
    }

    fn make_socks5() -> ProxyNode {
        ProxyNode::Socks5(Socks5Config {
            name: "socks-test".into(), server: "10.0.0.9".into(), port: 1080,
            username: "socks-user".into(), password: Some("socks-pass".into()),
            tls: Some(true), sni: Some("socks.example.com".into()),
            skip_cert_verify: Some(true), udp: Some(true),
        })
    }

    fn make_anytls() -> ProxyNode {
        ProxyNode::AnyTLS(AnyTLSConfig {
            name: "anytls-test".into(), server: "10.0.0.10".into(), port: 443,
            password: "anytls-pass".into(), sni: Some("anytls.example.com".into()),
            skip_cert_verify: Some(true), alpn: Some(vec!["h2".into()]),
        })
    }

    fn make_hysteria() -> ProxyNode {
        ProxyNode::Hysteria(HysteriaConfig {
            name: "hy1-test".into(), server: "10.0.0.11".into(), port: 443,
            auth_str: "hy1-auth".into(), protocol: Some("udp".into()),
            up: Some("50".into()), down: Some("100".into()),
            sni: Some("hy1.example.com".into()),
            skip_cert_verify: Some(true),
            alpn: Some(vec!["h3".into()]),
            obfs: Some("faketcp".into()),
            up_speed: None, down_speed: None, obfs_password: None,
            ports: None, fingerprint: None, ca: None, ca_str: None,
            recv_window_conn: None, recv_window: None,
            disable_mtu_discovery: None, fast_open: None, hop_interval: None,
        })
    }

    #[test]
    fn test_all_proxy_types_roundtrip() {
        let nodes = vec![
            make_ss(),
            make_ssr(),
            make_trojan(),
            make_vless(),
            make_hysteria2(),
            make_tuic(),
            make_snell(),
            make_http(),
            make_socks5(),
            make_anytls(),
            make_hysteria(),
            // VMess is already tested in test_legacy_conversion
        ];

        let mapping = parse_clash_yaml(&convert_proxies_to_clash(&nodes).unwrap());
        let proxies = mapping.get(ck("proxies")).unwrap().as_sequence().unwrap();
        assert_eq!(proxies.len(), 11, "all 11 proxy types should be present");

        // Every proxy must have name, server, port, type
        for proxy in proxies {
            let m = proxy.as_mapping().expect("each proxy must be a mapping");
            assert!(m.contains_key(ck("name")), "missing name");
            assert!(m.contains_key(ck("server")), "missing server");
            assert!(m.contains_key(ck("port")), "missing port");
            assert!(m.contains_key(ck("type")), "missing type");
        }

        // Verify protocol-specific output for a few key types
        let proxy_map: std::collections::HashMap<&str, &serde_yaml::Mapping> = proxies
            .iter()
            .filter_map(|p| {
                let m = p.as_mapping()?;
                Some((m.get(ck("name"))?.as_str()?, m))
            })
            .collect();

        // SS: cipher field
        let ss = proxy_map.get("ss-test").unwrap();
        assert_eq!(ss.get(ck("cipher")).unwrap().as_str().unwrap(), "chacha20-ietf-poly1305");
        assert_eq!(ss.get(ck("type")).unwrap().as_str().unwrap(), "ss");

        // Trojan: alpn as list, udp as bool
        let trojan = proxy_map.get("trojan-test").unwrap();
        assert_eq!(trojan.get(ck("type")).unwrap().as_str().unwrap(), "trojan");
        let alpn = trojan.get(ck("alpn")).unwrap().as_sequence().unwrap();
        assert_eq!(alpn.len(), 2);

        // Hysteria2: obfs fields
        let hy2 = proxy_map.get("hy2-test").unwrap();
        assert_eq!(hy2.get(ck("obfs")).unwrap().as_str().unwrap(), "salamander");
        assert!(hy2.contains_key(ck("obfs-password")));

        // Snell: version (u8 as number)
        let snell = proxy_map.get("snell-test").unwrap();
        assert!(snell.contains_key(ck("obfs")));
        // version may or may not be serialized

        // TUIC: udp-relay-mode and congestion-controller
        let tuic = proxy_map.get("tuic-test").unwrap();
        // Check that TUIC-specific fields make it through (they may use different key names)
        assert!(tuic.contains_key(ck("token")));
    }

    // ── Smart conversion with minimal config ──────────────────────────────────

    #[test]
    fn test_smart_conversion_minimal_config() {
        let ep = test_enriched("minimal", "3.0.0.1", 443, "min-uuid", 50, "US", "美国", "\u{1f1fa}\u{1f1f8}");

        let smart = SmartGroupConfig {
            enable: true,
            region_groups: false,
            auto_group_type: "url-test".into(),
            fallback_group: false,
            load_balance_group: false,
            generate_rules: false,
            ai_rules: false,
            streaming_rules: false,
            social_rules: false,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: false,
            custom_rules: vec![],
        };

        let mapping = parse_clash_yaml(&convert_enriched_to_clash(&[ep], Some(&smart)).unwrap());
        let groups = mapping.get(ck("proxy-groups")).unwrap().as_sequence().unwrap();
        // Always at minimum: region auto group, region select group, Proxy group
        assert!(groups.len() >= 3, "expected at least 3 groups, got {}", groups.len());
        let group_names: Vec<&str> = groups
            .iter()
            .filter_map(|g| g.as_mapping()?.get(ck("name"))?.as_str())
            .collect();
        assert!(group_names.contains(&"Proxy"), "default Proxy group should exist");
        // With fallback_group + load_balance_group off, no fallback/lb group expected
        assert!(!group_names.iter().any(|n| n.contains("Fallback")), "Fallback disabled but Fallback group present");
        assert!(!group_names.iter().any(|n| n.contains("Load-Balance")), "LB disabled but LB group present");
    }

    // ── Smart conversion with custom rules ────────────────────────────────────

    #[test]
    fn test_smart_conversion_custom_rules() {
        let ep = test_enriched("cust-node", "4.0.0.1", 443, "cust-uuid", 30, "DE", "德国", "\u{1f1e9}\u{1f1ea}");

        let smart = SmartGroupConfig {
            enable: true,
            region_groups: false,
            auto_group_type: "url-test".into(),
            fallback_group: false,
            load_balance_group: false,
            generate_rules: true,
            ai_rules: false,
            streaming_rules: false,
            social_rules: false,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: false,
            custom_rules: vec!["DOMAIN-SUFFIX,custom.example.com,Proxy".into()],
        };

        let mapping = parse_clash_yaml(&convert_enriched_to_clash(&[ep], Some(&smart)).unwrap());
        let rules = mapping.get(ck("rules")).unwrap().as_sequence().unwrap();
        let rule_strs: Vec<&str> = rules.iter().filter_map(|r| r.as_str()).collect();
        assert!(rule_strs.iter().any(|r| r.contains("custom.example.com")),
            "custom rules should appear in output: {:?}", rule_strs);
    }

    // ── YAML serialization validity (all converters produce valid YAML) ──────

    #[test]
    fn test_legacy_output_is_valid_yaml() {
        let nodes = vec![
            make_ss(),
            make_trojan(),
            make_hysteria2(),
        ];
        let yaml = convert_proxies_to_clash(&nodes).unwrap();
        let _parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)
            .expect("legacy output must be valid YAML");
    }

    #[test]
    fn test_smart_output_is_valid_yaml() {
        let ep = test_enriched("val-node", "5.0.0.1", 443, "val-uuid", 100, "FR", "法国", "\u{1f1eb}\u{1f1f7}");
        let smart = SmartGroupConfig {
            enable: true,
            region_groups: true,
            auto_group_type: "url-test".into(),
            fallback_group: true,
            load_balance_group: true,
            generate_rules: true,
            ai_rules: true,
            streaming_rules: true,
            social_rules: true,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: true,
            custom_rules: vec![],
        };
        let yaml = convert_enriched_to_clash(&[ep], Some(&smart)).unwrap();
        let _parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)
            .expect("smart output must be valid YAML");
    }
}
