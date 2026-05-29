use regex::Regex;

use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::RssCrawlConfig;
use crate::config::SettingsConfig;

pub async fn crawl_rss(
    config: &RssCrawlConfig,
    settings: &SettingsConfig,
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
