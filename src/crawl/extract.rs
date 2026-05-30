use regex::Regex;
use std::collections::HashSet;

/// Extract proxy subscription URLs and raw proxy lines from arbitrary text.
///
/// Matches:
/// - v2board / SSPanel panel subscribe APIs
/// - Clash / sing-box subscription endpoints
/// - Direct proxy links (12+ protocols)
/// - Comment-marked subscribe URLs
/// - Generic subscription paths
/// - Proxy panel admin paths
/// - Base64-encoded subscription data
/// - Raw proxy lines (IP:PORT)
pub fn extract_subscribes(content: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut results: Vec<String> = Vec::new();

    let patterns = [
        // SSPanel / v2board / similar panels: subscribe tokens, links, short-IDs
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?(?:/(?:index\.php)?)?/api/v[12]/(?:client/subscribe|user/getSubscribe)\?token=[a-zA-Z0-9]{16,48}",
        // Link-based subscriptions: /link/xxx?sub=1, /link/xxx?mu=1, /s/xxx
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:link/[a-zA-Z0-9]+\?(?:sub|mu|clash)=\d|s(?:ub)?/[a-zA-Z0-9]{24,48})",
        // Clash / sing-box subscription endpoints
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/sub\?(?:\S+)?(?:target=|flag=)\S+",
        // Generic subscribe keyword in URL
        r#"https?://[^\s"\'<>]+(?:subscribe|subscription|sub\?)[^\s"\'<>]{8,}"#,
        // Direct proxy links (all supported protocols)
        r"(?:vmess|trojan|ss|ssr|snell|hysteria2?|vless|tuic|anytls|socks5|http|https?|wireguard)://[a-zA-Z0-9:.?+=@%&#_\-/]{10,}",
        // Common proxy panel admin/subscribe paths (SSPanel, v2board, Proxypanel, etc.)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:admin/)?(?:api/v1/pay|api/v1/user|api/v1/server|api/v1/guest|api/v1/plan|api/v1/order|api/v1/ticket)\S*",
        // subscribe URL patterns with shorter tokens (8+ chars)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/api/v1/client/subscribe\?token=[a-zA-Z0-9]{8,}",
        // Clash proxy provider URLs
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:clash|provider|proxy|node)/[a-zA-Z0-9?&=_\-./]+",
        // v2rayN / v2rayNG subscription format (base64 encoded in URL path)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/sub/[a-zA-Z0-9+/=_-]{20,}",
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for m in re.find_iter(content) {
                let s = m.as_str().trim().to_string();
                if seen.insert(s.clone()) {
                    results.push(s);
                }
            }
        }
    }

    // Comment-marked subscribe URLs: Clash config headers, Chinese markers
    if let Ok(re) = Regex::new(r#"(?m)^[#;]\s*(?:!MANAGED-CONFIG|订阅链接|subscribe)[^\n]*?(https?://[^\s"'<>]+)"#) {
        for cap in re.captures_iter(content) {
            if let Some(url_match) = cap.get(1) {
                let s = url_match.as_str().trim().to_string();
                if seen.insert(s.clone()) {
                    results.push(s);
                }
            }
        }
    }

    // Raw proxy lines (IP:PORT format)
    if let Ok(re) = Regex::new(
        r"(?m)^\s*(?:(?:socks5|http|https|socks4|socks4a)://)?(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[\da-fA-F:]+]):\d{2,5}\s*$",
    ) {
        for m in re.find_iter(content) {
            let s = m.as_str().trim().to_string();
            if !results.contains(&s) {
                results.push(s);
            }
        }
    }

    // Base64-encoded subscription data
    if let Ok(re) = Regex::new(r"(?:[A-Za-z0-9+/]{80,}={0,2})") {
        for m in re.find_iter(content) {
            let s = m.as_str().trim().to_string();
            if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.as_bytes())
                && let Ok(text) = String::from_utf8(decoded)
                    && text.contains("://") && text.len() > 40
                        && seen.insert(s.clone()) {
                            results.push(s);
                        }
        }
    }

    results
}
