use std::sync::Arc;

use regex::Regex;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;

use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::RssCrawlConfig;
use crate::config::SettingsConfig;
use crate::proxy::ProxyNode;

pub async fn crawl_rss(
    config: &RssCrawlConfig,
    settings: &SettingsConfig,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Vec<String> {
    let urls = &config.urls;
    if urls.is_empty() {
        return Vec::new();
    }

    let client = match build_crawl_client(settings.socks_proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[rss] failed to build HTTP client: {}", e);
            return Vec::new();
        }
    };

    let sem = Arc::new(Semaphore::new(5));
    let mut handles = Vec::with_capacity(urls.len());

    for url in urls {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.clone();
        let inline_tx = inline_tx.clone();

        handles.push(tokio::spawn(async move {
            let _guard = permit;
            log::debug!("[rss] GET feed: {}", url);
            let resp = match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    log::warn!("[rss] feed {} returned HTTP {}", url, r.status());
                    return Vec::new();
                }
                Err(e) => {
                    log::warn!("[rss] failed to fetch feed {}: {}", url, e);
                    return Vec::new();
                }
            };

            let body = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    log::warn!("[rss] failed to read body from {}: {}", url, e);
                    return Vec::new();
                }
            };

            let content_fields = extract_rss_content(&body);
            let mut feed_results = Vec::new();
            for field in &content_fields {
                let mut inline = Vec::new();
                feed_results.extend(extract_subscribes(field, &mut inline));
                for p in inline { let _ = inline_tx.send(p); }
            }
            feed_results
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(urls) = handle.await {
            results.extend(urls);
            if results.len() >= config.limit {
                break;
            }
        }
    }

    results.truncate(config.limit);
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

    let re_item = Regex::new(r"(?s)<item>(.*?)</item>").ok();
    let re_desc = Regex::new(r"(?s)<description[^>]*>(.*?)</description>").ok();
    let re_cencoded = Regex::new(r"(?s)<content:encoded[^>]*>(.*?)</content:encoded>").ok();
    let re_entry = Regex::new(r"(?s)<entry>(.*?)</entry>").ok();
    let re_content = Regex::new(r"(?s)<content[^>]*>(.*?)</content>").ok();
    let re_summary = Regex::new(r"(?s)<summary[^>]*>(.*?)</summary>").ok();

    if let Some(ref re) = re_item {
        for cap in re.captures_iter(xml) {
            if let Some(item_xml) = cap.get(1) {
                let item_str = item_xml.as_str();
                if let Some(ref desc_re) = re_desc {
                    for desc_cap in desc_re.captures_iter(item_str) {
                        if let Some(desc) = desc_cap.get(1) {
                            let text = desc.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
                if let Some(ref ce_re) = re_cencoded {
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

    if let Some(ref re) = re_entry {
        for cap in re.captures_iter(xml) {
            if let Some(entry_xml) = cap.get(1) {
                let entry_str = entry_xml.as_str();
                if let Some(ref ct_re) = re_content {
                    for ct_cap in ct_re.captures_iter(entry_str) {
                        if let Some(content) = ct_cap.get(1) {
                            let text = content.as_str().trim();
                            if !text.is_empty() {
                                contents.push(strip_html(text));
                            }
                        }
                    }
                }
                if let Some(ref sm_re) = re_summary {
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
