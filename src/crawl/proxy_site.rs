use regex::Regex;

use tokio::sync::mpsc;

use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::ProxySiteConfig;
use crate::config::SettingsConfig;
use crate::proxy::ProxyNode;

pub async fn crawl_proxy_site(
    config: &ProxySiteConfig,
    settings: &SettingsConfig,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
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

    log::debug!("[proxy_site] fetched {} bytes from {}, extracting URLs", body.len(), url);
    let mut inline = Vec::new();
    let mut results = extract_subscribes(&body, &mut inline);
    for p in inline { let _ = inline_tx.send(p); }
    log::info!("[proxy_site] {}: extracted {} subscribe/proxy URLs ({} bytes)", url, results.len(), body.len());

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
