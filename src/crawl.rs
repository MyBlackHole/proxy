use regex::Regex;
use std::sync::Arc;

use crate::config::{
    DiscordCrawlConfig, PageCrawlConfig, ProxySiteConfig, RssCrawlConfig,
};
use crate::error::*;

#[derive(Debug, Clone)]
pub enum SubscribeStatus {
    Valid {
        upload: u64,
        download: u64,
        total: u64,
        expire: Option<u64>,
    },
    Invalid(String),
    Expired,
}

pub fn is_valid_subscribe(status: &SubscribeStatus) -> bool {
    matches!(status, SubscribeStatus::Valid { .. })
}

pub fn is_expired(status: &SubscribeStatus) -> bool {
    matches!(status, SubscribeStatus::Expired)
}

pub fn build_crawl_client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10));
    if let Some(proxy_url) = proxy {
        let p = reqwest::Proxy::all(proxy_url)
            .map_err(|e| AppError::InvalidProxy(e.to_string()))?;
        builder = builder.proxy(p);
    }
    Ok(builder.build()?)
}

pub fn extract_subscribes(content: &str) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();

    // ── Subscription URL patterns ──
    // 1. v2board / SSPanel / common panel subscribe APIs
    // 2. Clash / sing-box subscription endpoints
    // 3. Direct proxy links (12+ protocols)
    // 4. Comment-marked subscribe URLs
    // 5. Generic subscription paths (often embedded in HTML/JSON)
    // 6. Proxy panel admin paths (v2board, SSPanel, Proxypanel, etc.)
    // 7. Base64-encoded subscription data (inline)
    // 8. Raw proxy lines (IP:PORT)
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
        r"(?:vmess|trojan|ss|ssr|snell|hysteria2?|vless|tuic|anytls|socks5|http|https?)://[a-zA-Z0-9:.?+=@%&#_\-/]{10,}",
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
                if !results.contains(&s) {
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
                if !results.contains(&s) {
                    results.push(s);
                }
            }
        }
    }

    // ── Raw proxy lines (IP:PORT format) ──
    // Match lines like: 192.168.1.1:8080, 1.2.3.4:443, etc.
    // With optional protocol prefix: socks5://1.2.3.4:1080, http://1.2.3.4:3128
    if let Ok(re) = Regex::new(
        r"(?m)^\s*(?:(?:socks5|http|https|socks4|socks4a)://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\s*$",
    ) {
        for m in re.find_iter(content) {
            let s = m.as_str().trim().to_string();
            if !results.contains(&s) {
                results.push(s);
            }
        }
    }

    // Base64-encoded subscription data: large base64 blocks that decode to proxy content
    // Use a simple approach: find base64-like blocks and attempt decode via the base64 crate
    if let Ok(re) = Regex::new(r"(?:[A-Za-z0-9+/]{80,}={0,2})") {
        for m in re.find_iter(content) {
            let s = m.as_str().trim().to_string();
            // Try to decode with standard base64 - if it contains proxy URLs, include it
            if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.as_bytes()) {
                if let Ok(text) = String::from_utf8(decoded) {
                    if text.contains("://") && text.len() > 40 {
                        if !results.contains(&s) {
                            results.push(s);
                        }
                    }
                }
            }
        }
    }

    results
}

// ── Discord Crawler ────────────────────────────────────────────────────────
//
// Uses Discord Bot API to fetch messages from specified channels and
// extract proxy subscription URLs from message content.

pub async fn crawl_discord(
    config: &DiscordCrawlConfig,
    settings: &crate::config::SettingsConfig,
) -> Vec<String> {
    if config.bot_token.is_empty() {
        return Vec::new();
    }

    let client = match build_crawl_client(settings.socks_proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[discord] failed to build HTTP client: {}", e);
            return Vec::new();
        }
    };

    let mut results: Vec<String> = Vec::new();

    for channel_id in &config.channels {
        let url = format!(
            "https://discord.com/api/v10/channels/{}/messages?limit={}",
            channel_id, config.limit
        );

        let resp = match client
            .get(&url)
            .header("Authorization", format!("Bot {}", config.bot_token))
            .header("User-Agent", "DiscordBot (proxy-collector, 0.1.0)")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[discord] channel {} returned HTTP {}", channel_id, r.status());
                continue;
            }
            Err(e) => {
                log::warn!("[discord] failed to fetch channel {}: {}", channel_id, e);
                continue;
            }
        };

        let messages: Vec<serde_json::Value> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[discord] failed to parse messages for channel {}: {}", channel_id, e);
                continue;
            }
        };

        for msg in &messages {
                        if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                results.extend(extract_subscribes(content));
            }

            if let Some(embeds) = msg.get("embeds").and_then(|v| v.as_array()) {
                for embed in embeds {
                    if let Some(desc) = embed.get("description").and_then(|v| v.as_str()) {
                        results.extend(extract_subscribes(desc));
                    }
                    if let Some(title) = embed.get("title").and_then(|v| v.as_str()) {
                        results.extend(extract_subscribes(title));
                    }
                    if let Some(fields) = embed.get("fields").and_then(|v| v.as_array()) {
                        for field in fields {
                            if let Some(value) = field.get("value").and_then(|v| v.as_str()) {
                                results.extend(extract_subscribes(value));
                            }
                        }
                    }
                }
            }

            if let Some(attachments) = msg.get("attachments").and_then(|v| v.as_array()) {
                for attachment in attachments {
                    if let Some(url_str) = attachment.get("url").and_then(|v| v.as_str()) {
                        if url_str.ends_with(".txt") || url_str.ends_with(".yaml")
                            || url_str.ends_with(".yml") || url_str.ends_with(".conf")
                        {
                            if let Ok(resp) = client.get(url_str).send().await
                                && let Ok(text) = resp.text().await
                            {
                                results.extend(extract_subscribes(&text));
                            }
                        }
                    }
                }
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

// ── RSS/Atom Feed Crawler ──────────────────────────────────────────────────
//
// Fetches RSS/Atom feeds and extracts proxy subscription URLs from entry
// descriptions and content.

pub async fn crawl_rss(
    config: &RssCrawlConfig,
    settings: &crate::config::SettingsConfig,
) -> Vec<String> {
    if config.urls.is_empty() {
        return Vec::new();
    }

    let client = match build_crawl_client(settings.socks_proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[rss] failed to build HTTP client: {}", e);
            return Vec::new();
        }
    };

    let mut results: Vec<String> = Vec::new();
    let mut processed: usize = 0;

    for url in &config.urls {
        if processed >= config.limit {
            break;
        }

        let resp = match client.get(url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[rss] feed {} returned HTTP {}", url, r.status());
                continue;
            }
            Err(e) => {
                log::warn!("[rss] failed to fetch feed {}: {}", url, e);
                continue;
            }
        };

        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                log::warn!("[rss] failed to read body from {}: {}", url, e);
                continue;
            }
        };

        let content_fields = extract_rss_content(&body);
        for field in &content_fields {
            results.extend(extract_subscribes(field));
            processed += 1;
            if processed >= config.limit {
                break;
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

fn extract_rss_content(xml: &str) -> Vec<String> {
    let mut contents = Vec::new();

    let strip_html = |s: &str| -> String {
        let s = s
            .replace("<![CDATA[", "")
            .replace("]]>", "")
            .replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n");
        Regex::new(r"<[^>]+>")
            .map(|r| r.replace_all(&s, "").to_string())
            .unwrap_or(s)
    };

    if let Ok(re) = Regex::new(r"(?s)<item>(.*?)</item>") {
        for cap in re.captures_iter(xml) {
            if let Some(item_xml) = cap.get(1) {
                let item_str = item_xml.as_str();
                if let Ok(desc_re) = Regex::new(r"(?s)<description[^>]*>(.*?)</description>") {
                    for desc_cap in desc_re.captures_iter(item_str) {
                        if let Some(desc) = desc_cap.get(1) {
                            let text = desc.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
                if let Ok(ce_re) = Regex::new(r"(?s)<content:encoded[^>]*>(.*?)</content:encoded>") {
                    for ce_cap in ce_re.captures_iter(item_str) {
                        if let Some(ce) = ce_cap.get(1) {
                            let text = ce.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(re) = Regex::new(r"(?s)<entry>(.*?)</entry>") {
        for cap in re.captures_iter(xml) {
            if let Some(entry_xml) = cap.get(1) {
                let entry_str = entry_xml.as_str();
                if let Ok(ct_re) = Regex::new(r"(?s)<content[^>]*>(.*?)</content>") {
                    for ct_cap in ct_re.captures_iter(entry_str) {
                        if let Some(content) = ct_cap.get(1) {
                            let text = content.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
                if let Ok(sm_re) = Regex::new(r"(?s)<summary[^>]*>(.*?)</summary>") {
                    for sm_cap in sm_re.captures_iter(entry_str) {
                        if let Some(summary) = sm_cap.get(1) {
                            let text = summary.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
            }
        }
    }

    contents
}

// ── Proxy Aggregation Site Crawler ─────────────────────────────────────────
//
// Fetches known proxy aggregation pages and extracts proxy subscription URLs
// with optional include/exclude regex filtering.

pub async fn crawl_proxy_site(
    config: &ProxySiteConfig,
    settings: &crate::config::SettingsConfig,
) -> Vec<String> {
    let url = match &config.url {
        Some(u) => u,
        None => return Vec::new(),
    };

    let client = match build_crawl_client(settings.socks_proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[proxy_site] failed to build HTTP client: {}", e);
            return Vec::new();
        }
    };

    let resp = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            log::warn!("[proxy_site] {} returned HTTP {}", url, r.status());
            return Vec::new();
        }
        Err(e) => {
            log::warn!("[proxy_site] failed to fetch {}: {}", url, e);
            return Vec::new();
        }
    };

    let body = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[proxy_site] failed to read body from {}: {}", url, e);
            return Vec::new();
        }
    };

    let mut results = extract_subscribes(&body);

    // Apply include filter if set
    if !config.include.is_empty() {
        if let Ok(include_re) = Regex::new(&config.include) {
            results.retain(|s| include_re.is_match(s));
        } else {
            log::warn!("[proxy_site] invalid include regex: {}", config.include);
        }
    }

    // Apply exclude filter if set
    if !config.exclude.is_empty() {
        if let Ok(exclude_re) = Regex::new(&config.exclude) {
            results.retain(|s| !exclude_re.is_match(s));
        } else {
            log::warn!("[proxy_site] invalid exclude regex: {}", config.exclude);
        }
    }

    results.sort();
    results.dedup();
    results
}

pub async fn validate_subscribe(client: &reqwest::Client, url: &str) -> Result<SubscribeStatus> {
    let resp = client.get(url).send().await?;
    let status = resp.status();

    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(SubscribeStatus::Expired);
    }

    if !status.is_success() {
        return Ok(SubscribeStatus::Invalid(format!("HTTP {}", status.as_u16())));
    }

    let userinfo_header = resp.headers().get("subscription-userinfo").cloned();
    let content = resp.text().await?;
    if content.len() < 32 {
        return Ok(SubscribeStatus::Expired);
    }

    if let Some(userinfo) = userinfo_header
        && let Ok(header_str) = userinfo.to_str() {
            let mut upload = 0u64;
            let mut download = 0u64;
            let mut total = 0u64;
            let mut expire: Option<u64> = None;

            for part in header_str.split(';') {
                let kv: Vec<&str> = part.splitn(2, '=').collect();
                if kv.len() != 2 {
                    continue;
                }
                let key = kv[0].trim();
                let value = kv[1].trim();
                match key {
                    "upload" => upload = value.parse().unwrap_or(0),
                    "download" => download = value.parse().unwrap_or(0),
                    "total" => total = value.parse().unwrap_or(0),
                    "expire" => expire = value.parse().ok(),
                    _ => {}
                }
            }

            return Ok(SubscribeStatus::Valid {
                upload,
                download,
                total,
                expire,
            });
        }

    if content.contains("proxies:") || content.contains("://") {
        return Ok(SubscribeStatus::Valid {
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
    }

    Ok(SubscribeStatus::Invalid(
        "could not determine validity".into(),
    ))
}

pub async fn crawl_telegram(client: &reqwest::Client, channel: &str, pages: usize) -> Result<Vec<String>> {
    if pages > 1 {
        let page_count = get_telegram_page_count(client, channel).await.unwrap_or(0);
        if page_count == 0 {
            return Ok(Vec::new());
        }

        let mut values: Vec<i64> = (0..=page_count).rev().step_by(100).collect();
        values.truncate(pages);

        let mut results = Vec::new();
        for before in values {
            let url = format!("https://t.me/s/{}?before={}", channel, before);
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await {
                    results.extend(extract_subscribes(&text));
                }
        }

        results.sort();
        results.dedup();
        return Ok(results);
    }

    let url = format!("https://t.me/s/{}", channel);
    let resp = client.get(&url).send().await?;
    let text = resp.text().await?;
    Ok(extract_subscribes(&text))
}

async fn get_telegram_page_count(client: &reqwest::Client, channel: &str) -> Result<i64> {
    let url = format!("https://t.me/s/{}", channel);
    let resp = client.get(&url).send().await?;
    let text = resp.text().await?;

    let pattern = format!(
        r#"<link\s+rel="canonical"\s+href="/s/{}\?before=(\d+)">"#,
        regex::escape(channel)
    );
    let re = Regex::new(&pattern).map_err(|e| AppError::InvalidConfig(e.to_string()))?;

    if let Some(caps) = re.captures(&text)
        && let Some(before) = caps.get(1)
            && let Ok(n) = before.as_str().parse::<i64>() {
                return Ok(n);
            }

    Ok(0)
}

/// Extended version of `crawl_telegram` that also fetches historical messages
/// based on the given `history_depth`. Calls the original `crawl_telegram` for
/// the standard pages, then goes back further in history.
pub async fn crawl_telegram_history(
    client: &reqwest::Client,
    channel: &str,
    pages: usize,
    history_depth: usize,
) -> Result<Vec<String>> {
    let mut results = crawl_telegram(client, channel, pages).await?;

    if history_depth > 0 {
        // Use the page-count technique to go further back in history
        let extra_pages = history_depth.min(50);
        if let Ok(page_count) = get_telegram_page_count(client, channel).await {
            if page_count > 0 {
                let values: Vec<i64> = (0..=page_count)
                    .rev()
                    .step_by(100)
                    .skip(pages + 1) // skip pages already fetched by crawl_telegram
                    .take(extra_pages)
                    .collect();

                for before in values {
                    let url = format!("https://t.me/s/{}?before={}", channel, before);
                    if let Ok(resp) = client.get(&url).send().await
                        && let Ok(text) = resp.text().await
                    {
                        results.extend(extract_subscribes(&text));
                    }
                }
            }
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

pub async fn crawl_github(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
    token: &str,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let mut file_urls = Vec::new();

    for page in 1..=pages {
        let url = format!(
            "https://api.github.com/search/code?q={}&sort=indexed&order=desc&per_page=50&page={}",
            encoded, page
        );

        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str()) {
                    file_urls.push(html_url.to_string());
                }
            }
        }
    }

    let mut results = Vec::new();
    for file_url in &file_urls {
        if let Ok(resp) = client.get(file_url).send().await
            && let Ok(text) = resp.text().await {
                results.extend(extract_subscribes(&text));
            }
    }

    let issues_url = format!(
        "https://api.github.com/search/issues?q={}&sort=created&order=desc&per_page=50&page=1",
        encoded
    );
    if let Ok(resp) = client
        .get(&issues_url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        && let Ok(body) = resp.json::<serde_json::Value>().await
            && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str())
                        && let Ok(resp) = client.get(html_url).send().await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                }
            }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Search file contents in GitHub repositories for proxy subscription URLs.
/// Uses the GitHub code search API: GET /search/code?q={query}+repo:{owner}/{repo}
/// This is called when `GithubCrawlConfig.search_files` is true.
pub async fn crawl_github_search_files(
    client: &reqwest::Client,
    search_repos: &[String],
    query: &str,
    token: &str,
) -> Vec<String> {
    if search_repos.is_empty() || query.is_empty() {
        return Vec::new();
    }

    let encoded: String =
        percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let mut results = Vec::new();

    for repo_full in search_repos {
        let search_url = format!(
            "https://api.github.com/search/code?q={}+repo:{}&per_page=50&page=1",
            encoded, repo_full
        );

        let resp = match client
            .get(&search_url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[github_search_files] repo {} returned HTTP {}", repo_full, r.status());
                continue;
            }
            Err(e) => {
                log::warn!("[github_search_files] failed to search repo {}: {}", repo_full, e);
                continue;
            }
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[github_search_files] failed to parse response for {}: {}", repo_full, e);
                continue;
            }
        };

        let items = match body.get("items").and_then(|v| v.as_array()) {
            Some(i) => i,
            None => continue,
        };

        for item in items {
            let html_url = match item.get("html_url").and_then(|v| v.as_str()) {
                Some(u) => u.to_string(),
                None => continue,
            };

            if let Ok(resp) = client.get(&html_url).send().await
                && let Ok(text) = resp.text().await
            {
                results.extend(extract_subscribes(&text));
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

pub async fn crawl_github_repo(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    commits: usize,
    token: &str,
) -> Result<Vec<String>> {
    let per_page = commits.max(1);
    let url = format!(
        "https://api.github.com/repos/{}/{}/commits?per_page={}",
        owner, repo, per_page
    );

    let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let commits_data: Vec<serde_json::Value> = resp.json().await?;
    let mut results = Vec::new();

    for commit in &commits_data {
        let commit_url = match commit.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => continue,
        };

        if let Ok(resp) = client
            .get(commit_url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            && let Ok(body) = resp.json::<serde_json::Value>().await
                && let Some(files) = body.get("files").and_then(|v| v.as_array()) {
                    for file in files {
                        if let Some(patch) = file.get("patch").and_then(|v| v.as_str()) {
                            results.extend(extract_subscribes(patch));
                        }
                    }
                }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

pub async fn crawl_google(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let num_per_page = 100;
    let limit = (pages * num_per_page).min(1000);
    let mut results = Vec::new();

    let url_re = Regex::new(
        r#"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/?(?:<em(?:\s+)?class="qkunPe">/?)?api/v1/client/subscribe\?token(?:</em>)?=[a-zA-Z0-9]{16,32}"#,
    );
    let url_re = match url_re {
        Ok(r) => r,
        Err(_) => return Ok(results),
    };

    for start in (0..limit).step_by(num_per_page) {
        let url = format!(
            "https://www.google.com/search?q={}&hl=zh-CN&num={}&start={}",
            encoded, num_per_page, start
        );

        if let Ok(resp) = client
            .get(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            .send()
            .await
            && let Ok(text) = resp.text().await {
                let cleaned = text
                    .replace("\\n", "")
                    .replace("\\u003d", "=");

                if cleaned.contains("did not match any documents")
                    || cleaned.contains("找不到和您查询的")
                {
                    break;
                }

                for m in url_re.find_iter(&cleaned) {
                    let s = m
                        .as_str()
                        .replace("<em class=\"qkunPe\">", "")
                        .replace("</em>", "")
                        .replace("<em>", "")
                        .replace(' ', "");
                    let s = if let Some(rest) = s.strip_prefix("http://") {
                        format!("https://{}", rest)
                    } else {
                        s
                    };
                    if !results.contains(&s) {
                        results.push(s);
                    }
                }

                // Also find broader subscription/ proxy patterns in cleaned text
                results.extend(extract_subscribes(&cleaned));
            }
    }

    results.sort();
    results.dedup();

    Ok(results)
}

pub async fn crawl_yandex(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let base_url = format!(
        r#"https://yandex.com/search/?text="{}"&lr=10599&cee=1&within=2"#,
        encoded
    );
    let total_pages = pages.clamp(1, 20);
    let mut results = Vec::new();

    let re = Regex::new(
        r"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/<b>api</b>/<b>v</b><b>1</b>/<b>client</b>/<b>subscribe</b>\?<b>token</b>=[a-zA-Z0-9]{16,32}",
    );
    let re = match re {
        Ok(r) => r,
        Err(_) => return Ok(results),
    };

    for page in 0..total_pages {
        let url = format!("{}&p={}", base_url, page);

        if let Ok(resp) = client
            .get(&url)
            .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            .send()
            .await
            && let Ok(text) = resp.text().await {
                for m in re.find_iter(&text) {
                    let s = m
                        .as_str()
                        .replace("<b>", "")
                        .replace("</b>", "");
                    let s = if let Some(rest) = s.strip_prefix("http://") {
                        format!("https://{}", rest)
                    } else {
                        s
                    };
                    if !results.contains(&s) {
                        results.push(s);
                    }
                }

                // Also find broader subscription/ proxy patterns in cleaned text
                let cleaned = text.replace("<b>", "").replace("</b>", "").replace("<br>", "");
                results.extend(extract_subscribes(&cleaned));
            }
    }

    results.sort();
    results.dedup();

    Ok(results)
}

static TWITTER_BEARER: &str =
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

async fn get_twitter_guest_token(client: &reqwest::Client) -> Result<String> {
    let resp = client
        .get("https://twitter.com/")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await?;

    let text = resp.text().await?;
    let re = Regex::new(r"gt=([0-9]{19})")
        .map_err(|e| AppError::InvalidConfig(e.to_string()))?;

    if let Some(cap) = re.captures(&text)
        && let Some(gt) = cap.get(1) {
            return Ok(gt.as_str().to_string());
        }

    Err(AppError::Storage("could not extract twitter guest token".into()))
}

pub async fn crawl_twitter(
    client: &reqwest::Client,
    username: &str,
    count: usize,
) -> Result<Vec<String>> {
    let guest_token = get_twitter_guest_token(client).await?;
    let tweet_count = count.clamp(1, 100);

    let auth_header = format!("Bearer {}", TWITTER_BEARER);

    let user_variables = serde_json::json!({
        "screen_name": username,
        "withSafetyModeUserFields": true,
    });
    let features = serde_json::json!({
        "blue_business_profile_image_shape_enabled": true,
        "responsive_web_graphql_exclude_directive_enabled": true,
        "verified_phone_label_enabled": false,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
        "responsive_web_graphql_timeline_navigation_enabled": true,
    });

    let user_url = format!(
        "https://twitter.com/i/api/graphql/sLVLhk0bGj3MVFEKTdax1w/UserByScreenName?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&user_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&user_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let user_id = body["data"]["user"]["result"]["rest_id"]
        .as_str()
        .ok_or_else(|| AppError::Storage("could not find twitter user id".into()))?
        .to_string();

    let timeline_variables = serde_json::json!({
        "userId": user_id,
        "count": tweet_count,
        "includePromotedContent": false,
        "withClientEventToken": false,
        "withBirdwatchNotes": false,
        "withVoice": true,
        "withV2Timeline": true,
    });

    let timeline_url = format!(
        "https://twitter.com/i/api/graphql/P7qs2Sf7vu1LDKbzDW9FSA/UserMedia?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&timeline_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&timeline_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let text = body.to_string();
    let results = extract_subscribes(&text);

    Ok(results)
}

pub async fn crawl_pages(
    client: &reqwest::Client,
    urls: Vec<String>,
    page_config: &PageCrawlConfig,
) -> Result<Vec<String>> {
    let concurrency = page_config.concurrency;
    if concurrency > 1 {
        return crawl_pages_concurrent(client, &urls, page_config, concurrency).await;
    }

    let mut results = Vec::new();

    for url in &urls {
        if page_config.multiple && !page_config.placeholder.is_empty() {
            for i in page_config.start..=page_config.end {
                let expanded = url.replace(&page_config.placeholder, &i.to_string());
                if let Ok(resp) = client.get(&expanded).send().await
                    && let Ok(text) = resp.text().await {
                        results.extend(extract_subscribes(&text));
                        // Depth crawling: follow links on the page
                        if page_config.depth > 0 {
                            results.extend(crawl_page_depth(client, &text, page_config.depth - 1).await);
                        }
                    }
            }
        } else if let Ok(resp) = client.get(url).send().await
        && let Ok(text) = resp.text().await {
            results.extend(extract_subscribes(&text));
            // Depth crawling: follow links on the page
            if page_config.depth > 0 {
                results.extend(crawl_page_depth(client, &text, page_config.depth - 1).await);
            }
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

async fn crawl_pages_concurrent(
    client: &reqwest::Client,
    urls: &[String],
    page_config: &PageCrawlConfig,
    concurrency: usize,
) -> Result<Vec<String>> {
    let mut expanded_urls: Vec<String> = Vec::new();
    for url in urls {
        if page_config.multiple && !page_config.placeholder.is_empty() {
            for i in page_config.start..=page_config.end {
                let expanded = url.replace(&page_config.placeholder, &i.to_string());
                expanded_urls.push(expanded);
            }
        } else {
            expanded_urls.push(url.clone());
        }
    }

    if expanded_urls.is_empty() {
        return Ok(Vec::new());
    }

    let depth = page_config.depth;
    let client = client.clone();
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for url in expanded_urls {
        let client = client.clone();
        let permit = sem.clone().acquire_owned().await;

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let mut page_results = Vec::new();
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await
            {
                page_results.extend(extract_subscribes(&text));
                if depth > 0 {
                    page_results.extend(crawl_page_depth(&client, &text, depth - 1).await);
                }
            }
            page_results
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(page_results) = handle.await {
            results.extend(page_results);
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Recursively follow http/https links found in page content up to remaining depth
fn crawl_page_depth<'a>(client: &'a reqwest::Client, content: &'a str, remaining: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>> {
    Box::pin(async move {
        if remaining == 0 {
            return Vec::new();
        }

        let link_re = match Regex::new(r#"https?://[^\s"'<>]+"#) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for m in link_re.find_iter(content) {
            let link = m.as_str().trim().to_string();
            if !link.starts_with("http://") && !link.starts_with("https://") {
                continue;
            }
            // Skip already-known subscribe patterns (already handled by extract_subscribes)
            if link.contains("subscribe") || link.contains("token=") || link.contains("vmess://") {
                continue;
            }
            if !seen.insert(link.clone()) {
                continue;
            }
            if seen.len() > 20 {
                break; // limit link-following per page
            }

            if let Ok(resp) = client.get(&link).send().await
                && let Ok(text) = resp.text().await {
                    results.extend(extract_subscribes(&text));
                    if remaining > 1 {
                        results.extend(crawl_page_depth(client, &text, remaining - 1).await);
                    }
                }
        }

        results
    })
}

/// Search GitHub Gists for proxy-related content
pub async fn crawl_github_gists(
    client: &reqwest::Client,
    query: &str,
    token: &str,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let url = format!(
        "https://api.github.com/search/code?q={}+language:text&per_page=50&page=1",
        encoded
    );
    // Also search gists directly
    let gist_url = format!(
        "https://api.github.com/gists/public?per_page=50&page=1"
    );

    let mut results = Vec::new();

    // Search gist content via code search (limited, but catches gists indexed by GitHub)
    if let Ok(resp) = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        && let Ok(body) = resp.json::<serde_json::Value>().await
            && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str())
                        && let Ok(resp) = client.get(html_url).send().await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                }
            }

    // Fetch recent public gists and scan their raw content
    if let Ok(resp) = client
        .get(&gist_url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        && let Ok(gists) = resp.json::<Vec<serde_json::Value>>().await {
                for gist in &gists {
                    if let Some(files) = gist.get("files").and_then(|v| v.as_object()) {
                        for (_name, file) in files {
                            if let Some(raw_url) = file.get("raw_url").and_then(|v| v.as_str()) {
                                // Only fetch files that look like proxy configs
                                if raw_url.contains(".yaml") || raw_url.contains(".yml")
                                    || raw_url.contains(".txt") || raw_url.contains(".conf")
                                    || raw_url.contains("config") || raw_url.contains("proxy")
                                {
                                    if let Ok(resp) = client.get(raw_url).send().await
                                        && let Ok(text) = resp.text().await {
                                            results.extend(extract_subscribes(&text));
                                        }
                                }
                            }
                        }
                    }
                }
            }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Search GitHub topics for proxy-related repositories, scan their READMEs
pub async fn crawl_github_topics(
    client: &reqwest::Client,
    topics: &[String],
    token: &str,
) -> Vec<String> {
    if topics.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();
    for topic in topics {
        if topic.is_empty() {
            continue;
        }
        let encoded: String = percent_encoding::utf8_percent_encode(topic, percent_encoding::NON_ALPHANUMERIC).to_string();
        let url = format!(
            "https://api.github.com/search/repositories?q=topic:{}&sort=updated&order=desc&per_page=20&page=1",
            encoded
        );

        if let Ok(resp) = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            && let Ok(body) = resp.json::<serde_json::Value>().await
                && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                    for item in items {
                        let full_name = match item.get("full_name").and_then(|v| v.as_str()) {
                            Some(n) => n.to_string(),
                            None => continue,
                        };
                        // Fetch README
                        let readme_url = format!(
                            "https://api.github.com/repos/{}/readme",
                            full_name
                        );
                        if let Ok(resp) = client
                            .get(&readme_url)
                            .header("Accept", "application/vnd.github.raw")
                            .header("Authorization", format!("Bearer {}", token))
                            .send()
                            .await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                    }
                }
    }

    results.sort();
    results.dedup();
    results
}

/// Search Twitter by keyword using the GraphQL search endpoint
pub async fn crawl_twitter_search(
    client: &reqwest::Client,
    query: &str,
    count: usize,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let guest_token = get_twitter_guest_token(client).await?;
    let tweet_count = count.clamp(1, 100);
    let auth_header = format!("Bearer {}", TWITTER_BEARER);

    let features = serde_json::json!({
        "blue_business_profile_image_shape_enabled": true,
        "responsive_web_graphql_exclude_directive_enabled": true,
        "verified_phone_label_enabled": false,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
        "responsive_web_graphql_timeline_navigation_enabled": true,
    });

    let search_variables = serde_json::json!({
        "rawQuery": query,
        "count": tweet_count,
        "product": "Top",
        "includePromotedContent": false,
    });

    let search_url = format!(
        "https://twitter.com/i/api/graphql/gkjsKepM6glHm36JjW4V3A/SearchTimeline?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&search_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&search_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let text = body.to_string();
    let results = extract_subscribes(&text);

    Ok(results)
}

/// Search public Telegram groups by keyword via t.me search
pub async fn crawl_telegram_search(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();

    let mut results = Vec::new();

    // Use Telegram Web search (t.me/search)
    for page in 0..pages {
        let page_str = if page == 0 { String::new() } else { page.to_string() };
        let _url = format!(
            "https://t.me/s/{}?before={}",
            encoded,
            if page == 0 { "" } else { &page_str }
        );

        if page == 0 {
            let url = format!("https://t.me/search?q={}", encoded);
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await {
                    results.extend(extract_subscribes(&text));
                }
        }

        // Also try t.me/s/ search via the search page
        let search_url = format!("https://t.me/search?q={}&page={}", encoded, page);
        if let Ok(resp) = client.get(&search_url).send().await
            && let Ok(text) = resp.text().await {
                results.extend(extract_subscribes(&text));
            }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Unified crawler source — each variant knows how to crawl itself
pub enum CrawlerSource {
    Telegram { name: String, pages: usize },
    GitHubSearch { query: String, pages: usize, token: String },
    GitHubUser { username: String, repo: String, depth: usize, token: String },
    Google { query: String, pages: usize },
    Yandex { query: String, pages: usize },
    Twitter { name: String, num: usize },
    CustomPage { url: String, config: PageCrawlConfig },
    GitHubRepo { username: String, repo_name: String, commits: usize, token: String },
}

impl CrawlerSource {
    pub async fn crawl(&self, client: &reqwest::Client) -> Result<Vec<String>> {
        match self {
            CrawlerSource::Telegram { name, pages } => crawl_telegram(client, name, *pages).await,
            CrawlerSource::GitHubSearch { query, pages, token } => crawl_github(client, query, *pages, token).await,
            CrawlerSource::GitHubUser { username, repo, depth, token } => crawl_github_repo(client, username, repo, *depth, token).await,
            CrawlerSource::Google { query, pages } => crawl_google(client, query, *pages).await,
            CrawlerSource::Yandex { query, pages } => crawl_yandex(client, query, *pages).await,
            CrawlerSource::Twitter { name, num } => crawl_twitter(client, name, *num).await,
            CrawlerSource::CustomPage { url, config } => {
                let urls = vec![url.clone()];
                crawl_pages(client, urls, config).await
            }
            CrawlerSource::GitHubRepo { username, repo_name, commits, token } => {
                crawl_github_repo(client, username, repo_name, *commits, token).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subscribes_direct_proxy_links() {
        let text = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ== trojan://password@1.2.3.4:443?peer=example.com";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 2, "should extract vmess and trojan links");
        assert!(results[0].starts_with("vmess://"));
        assert!(results[1].starts_with("trojan://"));
    }

    #[test]
    fn test_extract_subscribes_panel_api() {
        let text = "some text https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890 more";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should extract panel subscribe URL");
        assert!(results[0].contains("token="));
    }

    #[test]
    fn test_extract_subscribes_short_token() {
        let text = "url https://example.com/api/v1/client/subscribe?token=abc12345 more";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should extract subscribe URL with 8+ char token");
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line() {
        let text = "some text\n192.168.1.1:8080\nmore text\n";
        let results = extract_subscribes(text);
        assert!(!results.is_empty(), "should extract raw IP:PORT lines");
        assert!(results.contains(&"192.168.1.1:8080".to_string()));
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line_with_protocol() {
        let text = "socks5://10.0.0.1:1080\nhttp://192.168.1.100:3128";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 2, "should extract protocol-prefixed proxy lines");
        assert!(results.contains(&"socks5://10.0.0.1:1080".to_string()));
        assert!(results.contains(&"http://192.168.1.100:3128".to_string()));
    }

    #[test]
    fn test_extract_subscribes_base64_inline() {
        // A long base64 string (80+ chars) that decodes to text containing "://"
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg= ss://YWVzLTI1Ni1nY206cGFzczJAMTI3LjAuMC4xOjgzODg= ss://YWVzLTI1Ni1nY206cGFzczNAMjcuMC4wLjE6ODM4OA==";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw.as_bytes());
        // b64 is now a base64-encoded string that's much longer than 80 chars
        assert!(b64.len() > 80, "base64 string must be 80+ chars to match pattern");
        let text = format!("prefix {} suffix", b64);
        let results = extract_subscribes(&text);
        assert!(!results.is_empty(), "should extract base64 blocks containing proxy data");
    }

    #[test]
    fn test_extract_subscribes_empty() {
        let results = extract_subscribes("just some text without any proxy links");
        assert!(results.is_empty(), "should return empty for text without proxies");
    }

    #[test]
    fn test_extract_subscribes_no_duplicates() {
        let text = "vmess://abc123def456\nvmess://abc123def456";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should deduplicate results");
    }

    #[test]
    fn test_extract_subscribes_clash_provider() {
        let text = "proxies: https://example.com/clash/proxy/node1?flag=us";
        let results = extract_subscribes(text);
        assert!(!results.is_empty(), "should extract clash provider URLs");
    }
}
