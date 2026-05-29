use crate::error::*;
use crate::convert::ClashRule;
use serde_yaml::{Value, Mapping, Number};
use std::collections::HashMap;
use std::sync::Mutex;

/// Parsed result from downloading + converting a rule set
#[derive(Debug, Clone)]
pub struct ParsedRuleset {
    /// Target policy group
    pub group: String,
    /// Converted Clash rules (for inline use)
    pub rules: Vec<ClashRule>,
    /// Whether this ruleset is large enough to warrant a rule-provider
    pub large: bool,
    /// Auto-detected behavior type
    pub behavior: String,
}

/// Simple in-memory cache for fetched rulesets (keyed by URL)
static RULESET_CACHE: std::sync::LazyLock<Mutex<HashMap<String, ParsedRuleset>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Clear the ruleset cache
pub fn clear_cache() {
    if let Ok(mut cache) = RULESET_CACHE.lock() {
        cache.clear();
    }
}

/// Fetch and parse a rule set, supporting both remote URLs and local file paths.
///
/// Results are cached in-memory for the duration of the process to avoid
/// re-downloading the same ruleset multiple times.
pub async fn fetch_and_parse_ruleset(
    client: &reqwest::Client,
    cfg: &crate::config::RulesetConfig,
) -> Result<ParsedRuleset> {
    // Check cache first
    {
        if let Ok(cache) = RULESET_CACHE.lock() {
            if let Some(cached) = cache.get(&cfg.url) {
                return Ok(cached.clone());
            }
        }
    }

    let content = if cfg.is_remote() {
        fetch_remote_ruleset(client, &cfg.url).await?
    } else {
        read_local_ruleset(&cfg.url)?
    };

    let rules = parse_ruleset_content(&content)?;
    let behavior = cfg.behavior.clone().unwrap_or_else(|| detect_behavior(&rules));
    let large = rules.len() >= 50;

    let result = ParsedRuleset {
        group: cfg.group.clone(),
        rules,
        large,
        behavior,
    };

    // Cache the result
    if let Ok(mut cache) = RULESET_CACHE.lock() {
        cache.insert(cfg.url.clone(), result.clone());
    }

    Ok(result)
}

/// Download ruleset content from a URL
async fn fetch_remote_ruleset(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(AppError::Network(format!(
            "ruleset fetch failed: HTTP {}", resp.status()
        )));
    }
    let text = resp.text().await?;
    Ok(text)
}

/// Read ruleset content from a local file
fn read_local_ruleset(path: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| AppError::InvalidConfig(format!("Cannot read ruleset file '{}': {}", path, e)))
}

/// Parse ruleset content (Surge / Clash / Quantumult X) into uniform ClashRule vec
fn parse_ruleset_content(content: &str) -> Result<Vec<ClashRule>> {
    let trimmed = content.trim();

    // Try Clash rule-provider format (YAML with "payload:" key)
    if let Ok(yaml) = serde_yaml::from_str::<Value>(trimmed) {
        if let Some(payload) = yaml.get("payload").and_then(|v| v.as_sequence()) {
            let mut rules = Vec::with_capacity(payload.len());
            for entry in payload {
                if let Some(s) = entry.as_str() {
                    if let Some(rule) = parse_single_rule(s) {
                        rules.push(rule);
                    }
                }
            }
            if !rules.is_empty() {
                // Infer the target policy by scanning the Surge-style entries;
                // Clash format entries have no policy field, so leave group empty.
                return Ok(rules);
            }
        }
    }

    // Surge / Quantumult X / per-line format
    let mut rules = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line.starts_with(';') {
            continue;
        }
        if let Some(rule) = parse_single_rule(line) {
            rules.push(rule);
        }
    }

    Ok(rules)
}

/// Parse a single rule line into ClashRule.
/// Handles: Surge, Clash, and Quantumult X formats.
fn parse_single_rule(line: &str) -> Option<ClashRule> {
    let line = line.trim();

    // Skip non-rule lines
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }

    // Clash / Surge format: RULE_TYPE,value,policy
    // Also handles: RULE_TYPE,value (Clash rule-provider entry)
    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 2 {
        return None;
    }

    let rule_type = parts[0].trim().to_uppercase();
    let value = parts[1].trim();
    let policy = parts.get(2).map(|s| s.trim()).unwrap_or("Proxy");

    match rule_type.as_str() {
        // Standard Clash types — pass through
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6"
        | "SRC-IP-CIDR" | "GEOIP" | "MATCH" | "FINAL" | "DST-PORT" | "SRC-PORT"
        | "PROCESS-NAME" | "RULE-SET" | "AND" | "OR" | "NOT" => {
            if parts.len() == 3 || rule_type == "MATCH" || rule_type == "FINAL" {
                Some(ClashRule::Custom(format!("{},{},{}", rule_type, value, policy)))
            } else {
                Some(ClashRule::Custom(line.to_string()))
            }
        }

        // Quantumult X → Clash (use Custom since values are dynamic)
        "HOST" | "HOST-SUFFIX" => Some(ClashRule::Custom(format!("DOMAIN-SUFFIX,{},{}", value, policy))),
        "HOST-KEYWORD" => Some(ClashRule::Custom(format!("DOMAIN-KEYWORD,{},{}", value, policy))),
        "IP6-CIDR" => Some(ClashRule::Custom(format!("IP-CIDR6,{},{}", value, policy))),
        "USER-AGENT" => Some(ClashRule::Custom(format!("USER-AGENT,{},{}", value, policy))),

        // Surge-specific
        "URL-REGEX" => Some(ClashRule::Custom(format!("URL-REGEX,{},{}", value, policy))),

        _ => None,
    }
}

fn detect_behavior(rules: &[ClashRule]) -> String {
    let mut has_domain = false;
    let mut has_ip = false;
    let mut has_other = false;

    for rule in rules {
        let s = rule.to_rule_string();
        let upper = s.to_uppercase();
        if upper.starts_with("DOMAIN") || upper.starts_with("HOST") {
            has_domain = true;
        } else if upper.starts_with("IP-CIDR") || upper.starts_with("IP6-CIDR") {
            has_ip = true;
        } else {
            has_other = true;
        }
    }

    // Mix of domain + ip + other → classical
    let mut types = 0u8;
    if has_domain { types += 1; }
    if has_ip { types += 1; }
    if has_other { types += 1; }

    if types > 1 || has_other {
        "classical".into()
    } else if has_ip {
        "ipcidr".into()
    } else {
        "domain".into()
    }
}

/// Generate a YAML rule-provider entry for the given ruleset
pub fn generate_rule_provider(
    name: &str,
    url: &str,
    interval: u64,
    behavior: &str,
) -> Value {
    let provider_name = sanitize_provider_name(name);

    let mut provider = Mapping::new();
    provider.insert("type".into(), "http".into());
    provider.insert("behavior".into(), behavior.into());
    provider.insert("url".into(), url.into());
    provider.insert("path".into(), format!("./providers/{}.yaml", provider_name).into());
    provider.insert("interval".into(), Value::Number(Number::from(interval)));

    let mut map = Mapping::new();
    map.insert(provider_name.into(), Value::Mapping(provider));

    Value::Mapping(map)
}

/// Generate the RULE-SET rule that references a rule-provider
pub fn rule_set_rule(provider_name: &str, group: &str) -> ClashRule {
    let name = sanitize_provider_name(provider_name);
    ClashRule::Custom(format!("RULE-SET,{},{}", name, group))
}

/// Sanitize a provider name to be Clash-safe (no spaces, no special chars)
fn sanitize_provider_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_surge_rule() {
        let rule = parse_single_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
        assert_eq!(rule.to_rule_string(), "DOMAIN-SUFFIX,google.com,Proxy");
    }

    #[test]
    fn test_parse_surge_with_direct() {
        let rule = parse_single_rule("DOMAIN-SUFFIX,baidu.com,DIRECT").unwrap();
        assert_eq!(rule.to_rule_string(), "DOMAIN-SUFFIX,baidu.com,DIRECT");
    }

    #[test]
    fn test_parse_quantumult_x_host() {
        let rule = parse_single_rule("HOST,example.com,Proxy").unwrap();
        assert_eq!(rule.to_rule_string(), "DOMAIN-SUFFIX,example.com,Proxy");
    }

    #[test]
    fn test_parse_quantumult_x_ip6() {
        let rule = parse_single_rule("IP6-CIDR,::1/128,Proxy").unwrap();
        assert_eq!(rule.to_rule_string(), "IP-CIDR6,::1/128,Proxy");
    }

    #[test]
    fn test_parse_clash_payload_entry() {
        let rule = parse_single_rule("DOMAIN,example.com").unwrap();
        assert_eq!(rule.to_rule_string(), "DOMAIN,example.com");
    }

    #[test]
    fn test_parse_comment_line() {
        assert!(parse_single_rule("# this is a comment").is_none());
        assert!(parse_single_rule("// also comment").is_none());
        assert!(parse_single_rule("").is_none());
    }

    #[test]
    fn test_parse_mixed_ruleset() {
        let content = "\
# Surge rules
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,youtube,Proxy
IP-CIDR,8.8.8.8/32,DIRECT

--Quantumult X style
HOST,netflix.com,Proxy
IP6-CIDR,2001::/32,Proxy";
        let rules = parse_ruleset_content(content).unwrap();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.to_rule_string().contains("google.com")));
        assert!(rules.iter().any(|r| r.to_rule_string().contains("netflix")));
    }

    #[test]
    fn test_parse_clash_yaml_ruleset() {
        let content = r#"
payload:
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-SUFFIX,youtube.com
  - IP-CIDR,8.8.8.8/32
"#;
        let rules = parse_ruleset_content(content).unwrap();
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn test_detect_behavior_domain() {
        let rules = vec![
            ClashRule::DomainSuffix("google.com", "Proxy"),
            ClashRule::DomainSuffix("youtube.com", "Proxy"),
        ];
        assert_eq!(detect_behavior(&rules), "domain");
    }

    #[test]
    fn test_detect_behavior_ipcidr() {
        let rules = vec![
            ClashRule::Custom("IP-CIDR,8.8.8.0/24,Proxy".into()),
            ClashRule::Custom("IP-CIDR6,::1/128,Proxy".into()),
        ];
        assert_eq!(detect_behavior(&rules), "ipcidr");
    }

    #[test]
    fn test_detect_behavior_classical() {
        let rules = vec![
            ClashRule::DomainSuffix("google.com", "Proxy"),
            ClashRule::Custom("IP-CIDR,8.8.8.0/24,Proxy".into()),
        ];
        assert_eq!(detect_behavior(&rules), "classical");
    }

    #[test]
    fn test_generate_rule_provider() {
        let provider = generate_rule_provider(
            "My Provider", "https://example.com/rules.yaml", 86400, "domain",
        );
        let map = provider.as_mapping().unwrap();
        assert!(map.contains_key("My_Provider"));
        let entry = map.get("My_Provider").unwrap().as_mapping().unwrap();
        assert_eq!(
            entry.get("type").unwrap().as_str().unwrap(),
            "http"
        );
        assert_eq!(
            entry.get("behavior").unwrap().as_str().unwrap(),
            "domain"
        );
        assert_eq!(
            entry.get("url").unwrap().as_str().unwrap(),
            "https://example.com/rules.yaml"
        );
        assert_eq!(
            entry.get("interval").unwrap().as_u64().unwrap(),
            86400
        );
    }

    #[test]
    fn test_sanitize_provider_name() {
        assert_eq!(sanitize_provider_name("My Provider!"), "My_Provider_");
        assert_eq!(sanitize_provider_name("Netflix"), "Netflix");
        assert_eq!(sanitize_provider_name(""), "");
    }
}
