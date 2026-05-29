use regex::Regex;

use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::ProxySiteConfig;
use crate::config::SettingsConfig;

pub async fn crawl_proxy_site(
    config: &ProxySiteConfig,
    settings: &SettingsConfig,
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
