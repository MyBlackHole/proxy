use regex::Regex;
use crate::config::PreprocessConfig;
use crate::proxy::*;

/// Deprecated/weak Shadowsocks ciphers that should be filtered out.
const DEPRECATED_CIPHERS: &[&str] = &[
    "rc4", "rc4-md5", "rc4-md5-6",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-cfb1", "aes-128-cfb8",
    "aes-192-cfb1", "aes-192-cfb8",
    "aes-256-cfb1", "aes-256-cfb8",
    "bf-cfb",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
    "seed-cfb",
    "salsa20", "chacha20",
];

/// Main entry point: apply the full pre-processing pipeline to enriched proxies.
///
/// Pipeline order:
/// 1. include/exclude regex filter
/// 2. deprecated encryption filter
/// 3. regex rename rules
/// 4. append_proxy_type prefix
/// 5. sort
///
/// Apply global include/exclude filter to proxies.
/// Unlike PreprocessConfig's include/exclude, this is applied at the settings level
/// before any per-group preprocessing.
pub fn apply_global_filter(
    proxies: Vec<EnrichedProxy>,
    include_pattern: &str,
    exclude_pattern: &str,
) -> Vec<EnrichedProxy> {
    let include_re = if include_pattern.is_empty() {
        None
    } else {
        match Regex::new(include_pattern) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("global filter: invalid include regex '{}': {}", include_pattern, e);
                None
            }
        }
    };

    let exclude_re = if exclude_pattern.is_empty() {
        None
    } else {
        match Regex::new(exclude_pattern) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("global filter: invalid exclude regex '{}': {}", exclude_pattern, e);
                None
            }
        }
    };

    proxies.into_iter().filter(|ep| {
        let name = ep.node.name();
        if let Some(ref re) = include_re && !re.is_match(name) {
            return false;
        }
        if let Some(ref re) = exclude_re && re.is_match(name) {
            return false;
        }
        true
    }).collect()
}

/// Strip leading emoji characters from a proxy name.
///
/// Matches common emoji Unicode ranges (flags, pictographs, symbols) at the
/// start of the string and removes them along with any following whitespace.
pub fn strip_emoji_prefix(name: &str) -> String {
    name.trim_start_matches(|c: char| {
        let v = c as u32;
        matches!(v,
            // Regional indicators (flag pairs like 🇯🇵)
            0x1F1E6..=0x1F1FF |
            // Miscellaneous Symbols, Emoticons, Transport, Pictographs etc.
            0x1F300..=0x1F9FF |
            // Dingbats / Miscellaneous Symbols
            0x2600..=0x27BF |
            // Variation Selectors (emoji presentation)
            0xFE00..=0xFE0F |
            // Zero-width joiner (for compound emoji)
            0x200D |
            // Enclosed Alphanumerics / CJK symbols (keycaps, etc.)
            0x20E3..=0x20E3 |
            // Combining Enclosing Marks
            0x20D0..=0x20FF |
            // Enclosed Ideographic Supplement
            0x1F200..=0x1F2FF)
    })
    .trim_start()
    .to_string()
}

/// Remove old emoji from all proxy names in the list.
pub fn remove_old_emoji_from_proxies(proxies: Vec<EnrichedProxy>) -> Vec<EnrichedProxy> {
    proxies.into_iter().map(|mut ep| {
        let new_name = strip_emoji_prefix(ep.node.name());
        ep.node.set_name(new_name);
        ep
    }).collect()
}

pub fn preprocess_proxies(
    proxies: Vec<EnrichedProxy>,
    cfg: &PreprocessConfig,
) -> Vec<EnrichedProxy> {
    let mut proxies = proxies;

    // Step 1: include/exclude regex filter
    proxies = apply_include_exclude(proxies, cfg);

    // Step 2: deprecated encryption filter
    if cfg.filter_deprecated {
        proxies = filter_deprecated_encryption(proxies);
    }

    // Step 3: regex rename
    if !cfg.rename.is_empty() {
        proxies = apply_rename(proxies, &cfg.rename);
    }

    // Step 4: append proxy type
    if cfg.append_proxy_type {
        proxies = append_proxy_type(proxies);
    }

    // Step 5: sort
    if !cfg.sort_by.is_empty() {
        proxies = apply_sort(proxies, &cfg.sort_by, &cfg.sort_order);
    }

    proxies
}

// ── Step 1: Include / Exclude ─────────────────────────────────────────────

fn apply_include_exclude(
    proxies: Vec<EnrichedProxy>,
    cfg: &PreprocessConfig,
) -> Vec<EnrichedProxy> {
    let include_re = if cfg.include.is_empty() {
        None
    } else {
        match Regex::new(&cfg.include) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("preprocess: invalid include regex '{}': {}", cfg.include, e);
                None
            }
        }
    };

    let exclude_re = if cfg.exclude.is_empty() {
        None
    } else {
        match Regex::new(&cfg.exclude) {
            Ok(re) => Some(re),
            Err(e) => {
                log::warn!("preprocess: invalid exclude regex '{}': {}", cfg.exclude, e);
                None
            }
        }
    };

    proxies.into_iter().filter(|ep| {
        let name = ep.node.name();
        // include: if set, name MUST match
        if let Some(ref re) = include_re
            && !re.is_match(name) {
                return false;
            }
        // exclude: if set, name MUST NOT match
        if let Some(ref re) = exclude_re
            && re.is_match(name) {
                return false;
            }
        true
    }).collect()
}

// ── Step 2: Deprecated Encryption Filter ───────────────────────────────────

fn filter_deprecated_encryption(
    proxies: Vec<EnrichedProxy>,
) -> Vec<EnrichedProxy> {
    proxies.into_iter().filter(|ep| {
        match &ep.node {
            ProxyNode::Shadowsocks(c) => {
                if DEPRECATED_CIPHERS.contains(&c.cipher.to_lowercase().as_str()) {
                    log::debug!("preprocess: filtering deprecated SS cipher '{}' for '{}'",
                        c.cipher, c.name);
                    return false;
                }
            }
            ProxyNode::ShadowsocksR(c) => {
                if DEPRECATED_CIPHERS.contains(&c.cipher.to_lowercase().as_str()) {
                    log::debug!("preprocess: filtering deprecated SSR cipher '{}' for '{}'",
                        c.cipher, c.name);
                    return false;
                }
            }
            _ => {}
        }
        true
    }).collect()
}

// ── Step 3: Regex Rename ───────────────────────────────────────────────────

fn apply_rename(
    proxies: Vec<EnrichedProxy>,
    rules: &[crate::config::RenameRule],
) -> Vec<EnrichedProxy> {
    let compiled: Vec<(Regex, String)> = rules.iter().filter_map(|rule| {
        match Regex::new(&rule.pattern) {
            Ok(re) => Some((re, rule.replace.clone())),
            Err(e) => {
                log::warn!("preprocess: invalid rename regex '{}': {}", rule.pattern, e);
                None
            }
        }
    }).collect();

    if compiled.is_empty() {
        return proxies;
    }

    proxies.into_iter().map(|mut ep| {
        let mut new_name = ep.node.name().to_string();
        for (re, replacement) in &compiled {
            new_name = re.replace_all(&new_name, replacement.as_str()).to_string();
        }
        ep.node.set_name(new_name);
        ep
    }).collect()
}

// ── Step 4: Append Proxy Type ──────────────────────────────────────────────

fn append_proxy_type(
    proxies: Vec<EnrichedProxy>,
) -> Vec<EnrichedProxy> {
    proxies.into_iter().map(|mut ep| {
        let prefix = proxy_type_prefix(&ep.node);
        let current_name = ep.node.name().to_string();
        // Only prepend if not already prefixed
        if !current_name.starts_with(prefix) {
            ep.node.set_name(format!("{}{}", prefix, current_name));
        }
        ep
    }).collect()
}

fn proxy_type_prefix(node: &ProxyNode) -> &'static str {
    match node {
        ProxyNode::Shadowsocks(_) => "SS-",
        ProxyNode::ShadowsocksR(_) => "SSR-",
        ProxyNode::VMess(_) => "VMess-",
        ProxyNode::Trojan(_) => "Trojan-",
        ProxyNode::VLESS(_) => "VLESS-",
        ProxyNode::Hysteria(_) => "Hysteria-",
        ProxyNode::Hysteria2(_) => "Hysteria2-",
        ProxyNode::Tuic(_) => "TUIC-",
        ProxyNode::Snell(_) => "Snell-",
        ProxyNode::Http(_) => "HTTP-",
        ProxyNode::Socks5(_) => "SOCKS5-",
        ProxyNode::AnyTLS(_) => "AnyTLS-",
        ProxyNode::WireGuard(_) => "WireGuard-",
    }
}

// ── Step 5: Sort ───────────────────────────────────────────────────────────

fn apply_sort(
    mut proxies: Vec<EnrichedProxy>,
    by: &str,
    order: &str,
) -> Vec<EnrichedProxy> {
    let desc = order == "desc";

    match by {
        "name" => {
            proxies.sort_by(|a, b| a.node.name().cmp(b.node.name()));
        }
        "type" => {
            proxies.sort_by(|a, b| {
                let at = proxy_type_prefix(&a.node);
                let bt = proxy_type_prefix(&b.node);
                at.cmp(bt)
            });
        }
        "latency" => {
            proxies.sort_by(|a, b| a.latency_ms.cmp(&b.latency_ms));
        }
        _ => {
            log::warn!("preprocess: unknown sort_by '{}' (use name/type/latency)", by);
            return proxies;
        }
    }

    if desc {
        proxies.reverse();
    }

    proxies
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_enriched(
        _name: &str, proto: ProxyNode, latency: u64, cc: &str,
    ) -> EnrichedProxy {
        let mut ep = EnrichedProxy::new(proto, latency);
        ep.country_code = cc.to_string();
        ep
    }

    fn make_ss(name: &str, cipher: &str) -> ProxyNode {
        ProxyNode::Shadowsocks(ShadowsocksConfig {
            name: name.into(),
            server: "1.2.3.4".into(),
            port: 443,
            cipher: cipher.into(),
            password: Some("pass".into()),
            plugin: None,
            plugin_opts: None,
            udp: None,
        })
    }

    fn make_vmess(name: &str) -> ProxyNode {
        ProxyNode::VMess(VMessConfig {
            name: name.into(),
            server: "1.2.3.4".into(),
            port: 443,
            uuid: "abc-123".into(),
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

    fn make_trojan(name: &str) -> ProxyNode {
        ProxyNode::Trojan(TrojanConfig {
            name: name.into(),
            server: "1.2.3.4".into(),
            port: 443,
            password: "pass".into(),
            sni: None,
            alpn: None,
            skip_cert_verify: None,
            udp: None,
            network: None,
            ws_path: None,
            ws_headers: None,
            grpc_service_name: None,
        })
    }

    fn make_ssr(name: &str, cipher: &str) -> ProxyNode {
        ProxyNode::ShadowsocksR(ShadowsocksRConfig {
            name: name.into(),
            server: "1.2.3.4".into(),
            port: 443,
            password: Some("pass".into()),
            cipher: cipher.into(),
            obfs: "tls1.2_ticket_auth".into(),
            obfs_param: "".into(),
            protocol: "auth_aes128_md5".into(),
            protocol_param: "".into(),
            udp: None,
        })
    }

    fn default_cfg() -> PreprocessConfig {
        PreprocessConfig::default()
    }

    // ── Include / Exclude ────────────────────────────────────────────────

    #[test]
    fn test_include_filter() {
        let mut cfg = default_cfg();
        cfg.include = "^US-".into();
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
            test_enriched("JP-01", make_vmess("JP-01"), 100, "JP"),
            test_enriched("US-02", make_vmess("US-02"), 100, "US"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|ep| ep.node.name().starts_with("US-")));
    }

    #[test]
    fn test_exclude_filter() {
        let mut cfg = default_cfg();
        cfg.exclude = "过期".into();
        let proxies = vec![
            test_enriched("日本 01", make_vmess("日本 01"), 100, "JP"),
            test_enriched("已过期节点", make_vmess("已过期节点"), 100, "JP"),
            test_enriched("新加坡 02", make_vmess("新加坡 02"), 100, "SG"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|ep| !ep.node.name().contains("过期")));
    }

    // ── Deprecated Cipher Filter ─────────────────────────────────────────

    #[test]
    fn test_filter_deprecated_ss() {
        let mut cfg = default_cfg();
        cfg.filter_deprecated = true;
        let proxies = vec![
            test_enriched("good", make_ss("good", "chacha20-ietf-poly1305"), 100, "US"),
            test_enriched("bad", make_ss("bad", "rc4-md5"), 100, "US"),
            test_enriched("cfb", make_ss("cfb", "aes-256-cfb"), 100, "US"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node.name(), "good");
    }

    #[test]
    fn test_filter_deprecated_ssr() {
        let mut cfg = default_cfg();
        cfg.filter_deprecated = true;
        let proxies = vec![
            test_enriched("good-ss", make_ss("good-ss", "chacha20-ietf-poly1305"), 100, "US"),
            test_enriched("bad-ssr", make_ssr("bad-ssr", "rc4"), 100, "US"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node.name(), "good-ss");
    }

    // ── Regex Rename ─────────────────────────────────────────────────────

    #[test]
    fn test_regex_rename() {
        let mut cfg = default_cfg();
        cfg.rename = vec![
            crate::config::RenameRule {
                pattern: r"^(\w+)-(\d+)$".into(),
                replace: "🇯🇵 JP $1 $2".into(),
            },
        ];
        let proxies = vec![
            test_enriched("tokyo-01", make_vmess("tokyo-01"), 100, "JP"),
            test_enriched("osaka-02", make_vmess("osaka-02"), 100, "JP"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result[0].node.name(), "🇯🇵 JP tokyo 01");
        assert_eq!(result[1].node.name(), "🇯🇵 JP osaka 02");
    }

    // ── Append Proxy Type ────────────────────────────────────────────────

    #[test]
    fn test_append_proxy_type() {
        let mut cfg = default_cfg();
        cfg.append_proxy_type = true;
        let proxies = vec![
            test_enriched("Tokyo", make_vmess("Tokyo"), 100, "JP"),
            test_enriched("SS-Node", make_ss("SS-Node", "chacha20-ietf-poly1305"), 100, "US"),
            test_enriched("Osaka", make_trojan("Osaka"), 100, "JP"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        assert_eq!(result[0].node.name(), "VMess-Tokyo");
        // "SS-Node" already starts with "SS-" → dedup prevents double prefix
        assert_eq!(result[1].node.name(), "SS-Node");
        assert_eq!(result[2].node.name(), "Trojan-Osaka");
    }

    // ── Sort ─────────────────────────────────────────────────────────────

    #[test]
    fn test_sort_by_name_asc() {
        let mut cfg = default_cfg();
        cfg.sort_by = "name".into();
        cfg.sort_order = "asc".into();
        let proxies = vec![
            test_enriched("Z", make_vmess("Z"), 100, "US"),
            test_enriched("A", make_vmess("A"), 100, "US"),
            test_enriched("M", make_vmess("M"), 100, "US"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        let names: Vec<&str> = result.iter().map(|ep| ep.node.name()).collect();
        assert_eq!(names, vec!["A", "M", "Z"]);
    }

    #[test]
    fn test_sort_by_latency_desc() {
        let mut cfg = default_cfg();
        cfg.sort_by = "latency".into();
        cfg.sort_order = "desc".into();
        let proxies = vec![
            test_enriched("slow", make_vmess("slow"), 500, "US"),
            test_enriched("fast", make_vmess("fast"), 50, "US"),
            test_enriched("mid", make_vmess("mid"), 200, "US"),
        ];
        let result = preprocess_proxies(proxies, &cfg);
        let names: Vec<&str> = result.iter().map(|ep| ep.node.name()).collect();
        assert_eq!(names, vec!["slow", "mid", "fast"]);
    }

    // ── Full Pipeline ────────────────────────────────────────────────────

    #[test]
    fn test_full_pipeline() {
        let mut cfg = default_cfg();
        cfg.include = "^(US|JP)".into();
        cfg.exclude = "过期".into();
        cfg.filter_deprecated = true;
        cfg.rename = vec![
            crate::config::RenameRule {
                pattern: r"^(\w+)-(\w+)$".into(),
                replace: "🇺🇸 $1 $2".into(),
            },
        ];
        cfg.append_proxy_type = true;
        cfg.sort_by = "name".into();
        cfg.sort_order = "asc".into();

        let proxies = vec![
            test_enriched("US-01", make_ss("US-01", "rc4-md5"), 100, "US"),
            test_enriched("JP-01", make_vmess("JP-01"), 50, "JP"),
            test_enriched("已过期-CN", make_vmess("已过期-CN"), 200, "CN"),
            test_enriched("US-02", make_trojan("US-02"), 80, "US"),
            test_enriched("DE-01", make_vmess("DE-01"), 30, "DE"),
        ];

        let result = preprocess_proxies(proxies, &cfg);

        // DE-01 excluded by include, 已过期 excluded by exclude
        // US-01 filtered by deprecated cipher
        // Only JP-01 and US-02 remain — with rename + append_proxy_type applied
        assert_eq!(result.len(), 2, "expected 2 proxies, got {}: {:?}",
            result.len(), result.iter().map(|ep| ep.node.name()).collect::<Vec<_>>());

        // Both sorted by name asc: "Trojan-..." (T) before "VMess-..." (V)
        assert_eq!(result[0].node.name(), "Trojan-🇺🇸 US 02");
        assert_eq!(result[1].node.name(), "VMess-🇺🇸 JP 01");
    }

    // ── Global Filter (Settings-level) ────────────────────────────────────

    #[test]
    fn test_global_filter_include_only() {
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
            test_enriched("JP-01", make_vmess("JP-01"), 50, "JP"),
            test_enriched("SG-01", make_vmess("SG-01"), 80, "SG"),
        ];
        let result = apply_global_filter(proxies, "^US", "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node.name(), "US-01");
    }

    #[test]
    fn test_global_filter_exclude_only() {
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
            test_enriched("JP-01", make_vmess("JP-01"), 50, "JP"),
            test_enriched("SG-01", make_vmess("SG-01"), 80, "SG"),
        ];
        let result = apply_global_filter(proxies, "", "^US");
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|ep| !ep.node.name().starts_with("US")));
    }

    #[test]
    fn test_global_filter_include_and_exclude() {
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
            test_enriched("US-过期", make_vmess("US-过期"), 100, "US"),
            test_enriched("JP-01", make_vmess("JP-01"), 50, "JP"),
            test_enriched("SG-01", make_vmess("SG-01"), 80, "SG"),
        ];
        let result = apply_global_filter(proxies, "^US", "过期");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node.name(), "US-01");
    }

    #[test]
    fn test_global_filter_no_match_returns_empty() {
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
        ];
        let result = apply_global_filter(proxies, "^JP", "");
        assert!(result.is_empty());
    }

    #[test]
    fn test_global_filter_empty_patterns_passthrough() {
        let proxies = vec![
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
        ];
        let result = apply_global_filter(proxies.clone(), "", "");
        assert_eq!(result.len(), 1);
    }

    // ── Emoji Stripping ───────────────────────────────────────────────────

    #[test]
    fn test_strip_emoji_prefix_no_emoji() {
        assert_eq!(strip_emoji_prefix("US-01"), "US-01");
        assert_eq!(strip_emoji_prefix(""), "");
        assert_eq!(strip_emoji_prefix("abc123"), "abc123");
    }

    #[test]
    fn test_strip_emoji_prefix_flag_emoji() {
        assert_eq!(strip_emoji_prefix("🇯🇵 JP-Tokyo"), "JP-Tokyo");
        assert_eq!(strip_emoji_prefix("🇺🇸US-Node"), "US-Node");
    }

    #[test]
    fn test_strip_emoji_prefix_misc_symbols() {
        assert_eq!(strip_emoji_prefix("📡 Relay-01"), "Relay-01");
        assert_eq!(strip_emoji_prefix("🎯 Direct"), "Direct");
    }

    #[test]
    fn test_strip_emoji_prefix_multiple_emoji() {
        assert_eq!(strip_emoji_prefix("🇯🇵🎯 JP-Direct"), "JP-Direct");
    }

    #[test]
    fn test_remove_old_emoji_from_proxies_basic() {
        let proxies = vec![
            test_enriched("🇯🇵 JP-Tokyo", make_vmess("🇯🇵 JP-Tokyo"), 100, "JP"),
            test_enriched("US-01", make_vmess("US-01"), 100, "US"),
            test_enriched("🇺🇸🇺🇸 US-02", make_vmess("🇺🇸🇺🇸 US-02"), 100, "US"),
        ];
        let result = remove_old_emoji_from_proxies(proxies);
        assert_eq!(result[0].node.name(), "JP-Tokyo");
        assert_eq!(result[1].node.name(), "US-01");
        assert_eq!(result[2].node.name(), "US-02");
    }

    #[test]
    fn test_remove_old_emoji_from_proxies_all_emoji_clears() {
        let proxies = vec![
            test_enriched("😀😃😄", make_vmess("😀😃😄"), 100, "JP"),
        ];
        let result = remove_old_emoji_from_proxies(proxies);
        // After stripping all emoji, name becomes empty
        assert!(result[0].node.name().chars().all(|c| !c.is_ascii()));
    }
}
