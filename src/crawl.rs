use regex::Regex;

use crate::config::PageCrawlConfig;
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

    let patterns = [
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+(?::\d+)?(?:(?:(?:/index.php)?/api/v1/client/subscribe\?token=[a-zA-Z0-9]{16,32})|(?:/link/[a-zA-Z0-9]+\?(?:sub|mu|clash)=\d)|(?:/(?:s|sub)/[a-zA-Z0-9]{32}))",
        r"https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+/sub\?(?:\S+)?target=\S+",
        r"(?:vmess|trojan|ss|ssr|snell|hysteria2|vless|hysteria|tuic|anytls)://[a-zA-Z0-9:.?+=@%&#_\-/]{10,}",
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

    if let Ok(re) = Regex::new(r#"(?m)^#(?:\s+)?(?:!MANAGED-CONFIG|订阅链接)[^\n]*?(https?://[^\s"'<>]+)"#) {
        for cap in re.captures_iter(content) {
            if let Some(url_match) = cap.get(1) {
                let s = url_match.as_str().trim().to_string();
                if !results.contains(&s) {
                    results.push(s);
                }
            }
        }
    }

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
            }
    }

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
            }
    }

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
    let mut results = Vec::new();

    for url in &urls {
        if page_config.multiple && !page_config.placeholder.is_empty() {
            for i in page_config.start..=page_config.end {
                let expanded = url.replace(&page_config.placeholder, &i.to_string());
                if let Ok(resp) = client.get(&expanded).send().await
                    && let Ok(text) = resp.text().await {
                        results.extend(extract_subscribes(&text));
                    }
            }
        } else if let Ok(resp) = client.get(url).send().await
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
