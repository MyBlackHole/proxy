use std::collections::HashSet;
use std::sync::LazyLock;
use regex::Regex;
use crate::proxy::ProxyNode;

/// Static collection of regex patterns for matching HTTP(S) subscription URLs.
///
/// Compiled once and reused across all `extract_subscribes` calls.
static SUBSCRIBE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let raw = [
        // SSPanel / v2board / similar panels: subscribe tokens, links, short-IDs
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?(?:/(?:index\.php)?)?/api/v[12]/(?:client/subscribe|user/getSubscribe)\?token=[a-zA-Z0-9]{16,48}",
        // Link-based subscriptions: /link/xxx?sub=1, /link/xxx?mu=1, /s/xxx
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:link/[a-zA-Z0-9]+\?(?:sub|mu|clash)=\d|s(?:ub)?/[a-zA-Z0-9]{24,48})",
        // Clash / sing-box subscription endpoints
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/sub\?(?:\S+)?(?:target=|flag=)\S+",
        // Generic subscribe keyword in URL
        r#"https?://[^\s"\'<>]+(?:subscribe|subscription|sub\?)[^\s"\'<>]{8,}"#,
        // Common proxy panel admin/subscribe paths (SSPanel, v2board, Proxypanel, etc.)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:admin/)?(?:api/v1/pay|api/v1/user|api/v1/server|api/v1/guest|api/v1/plan|api/v1/order|api/v1/ticket)\S*",
        // subscribe URL patterns with shorter tokens (8+ chars)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/api/v1/client/subscribe\?token=[a-zA-Z0-9]{8,}",
        // Clash proxy provider URLs
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?/(?:clash|provider|proxy|node)/[a-zA-Z0-9?&=_\-./]+",
        // v2rayN / v2rayNG subscription format (base64 encoded in URL path)
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/sub/[a-zA-Z0-9+/=_-]{20,}",
    ];
    raw.iter().filter_map(|p| Regex::new(p).ok()).collect()
});

/// Find subscription URLs in `content` using the compiled `SUBSCRIBE_PATTERNS`.
///
/// Deduplicates results via `seen` and appends new URLs to `results`.
fn find_subscribe_urls(content: &str, seen: &mut HashSet<String>, results: &mut Vec<String>) {
    for re in SUBSCRIBE_PATTERNS.iter() {
        for m in re.find_iter(content) {
            let s = m.as_str().trim().to_string();
            if seen.insert(s.clone()) {
                results.push(s);
            }
        }
    }
}

/// Detect and parse inline proxy content, appending parsed `ProxyNode`s to `out_inline`.
///
/// Uses `detect_format` to determine the content format, then `extract_links` to
/// obtain proxy URLs, and finally `parse_proxy_url` to convert each URL to a `ProxyNode`.
fn extract_inline_proxies(content: &str, out_inline: &mut Vec<ProxyNode>) {
    let fmt = crate::subscribe::detect_format(content.as_bytes());
    if fmt == crate::subscribe::SubscriptionFormat::Unknown {
        return;
    }
    let proxy_urls = crate::subscribe::extract_links(content, fmt);
    for url in proxy_urls {
        if let Ok(node) = crate::parser::parse_proxy_url(&url) {
            out_inline.push(node);
        }
    }
}

/// Extract proxy subscription URLs and inline proxy nodes from arbitrary text.
///
/// Returns subscription URLs as `Vec<String>`, and populates `out_inline` with
/// parsed proxy nodes found inline in the content (non-subscription proxy data).
///
///
/// Processing steps: pattern match subscribe URLs, decode base64 blocks,
/// detect inline non-base64 proxy content, match comment-marked URLs.
pub fn extract_subscribes(content: &str, out_inline: &mut Vec<ProxyNode>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    // Step 1: HTTP(S) subscribe URL patterns on raw content
    find_subscribe_urls(content, &mut seen, &mut results);

    // Step 2a: Base64 blocks → decode → format-detect → extract
    if let Ok(re) = Regex::new(r"(?:[A-Za-z0-9+/]{80,}={0,2})") {
        for m in re.find_iter(content) {
            if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, m.as_str().as_bytes())
                && let Ok(text) = String::from_utf8(decoded)
            {
                find_subscribe_urls(&text, &mut seen, &mut results);
                extract_inline_proxies(&text, out_inline);
            }
        }
    }

    // Step 2b: Non-base64 inline proxy content
    let has_clash       = content.contains("proxies:\n  - ");
    let has_json_arr    = content.trim().starts_with('[');
    let has_proxy_lines = content.lines()
        .filter(|l| crate::subscribe::PROXY_SCHEMES.iter().any(|s| l.trim().starts_with(s)))
        .count() >= 2;
    let has_surfboard   = content.contains("[Proxy]");
    let has_quantumult  = content.lines().any(|l| {
        let t = l.trim();
        t.starts_with("shadowsocks=") || t.starts_with("vmess=") || t.starts_with("trojan=")
    });

    if has_clash || has_json_arr || has_proxy_lines || has_surfboard || has_quantumult {
        extract_inline_proxies(content, out_inline);
    }

    // Step 3: Comment-marked subscribe URLs
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

    results
}
