use tokio::sync::mpsc;
use crate::error::*;
use crate::proxy::ProxyNode;
use super::extract_subscribes;

/// Structured proxy list from external APIs.
/// Each source returns IP:PORT pairs in various formats.
pub async fn crawl_proxy_apis(
    client: &reqwest::Client,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Result<Vec<String>> {
    let mut all_results = Vec::new();

    // Source 1: Geonode - free proxy API
    // Returns JSON: { "data": [ { "ip": "...", "port": ..., "protocols": [...] }, ... ] }
    let geonode_url = "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc";
    if let Ok(resp) = client.get(geonode_url)
        .header("User-Agent", "Mozilla/5.0")
        .send().await
        && let Ok(text) = resp.text().await
    {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(data) = json["data"].as_array() {
                for entry in data {
                    if let (Some(ip), Some(port), Some(protocols)) = (
                        entry["ip"].as_str(),
                        entry["port"].as_str(),
                        entry["protocols"].as_array(),
                    ) {
                        for proto in protocols {
                            if let Some(p) = proto.as_str() {
                                let line = format!("{}://{}:{}", p.to_lowercase(), ip, port);
                                all_results.push(line);
                            }
                        }
                    }
                }
            }
        // Also extract any subscribe URLs
        let mut inline = Vec::new();
        all_results.extend(extract_subscribes(&text, &mut inline));
        for p in inline { let _ = inline_tx.send(p); }
    }

    // Brief delay between sources
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Source 2: ProxyScrape - HTTP proxy list (text format, one IP:PORT per line)
    // Already configured as default proxy_sites, skip to avoid duplication

    // Source 3: OpenProxySpace - free proxy JSON
    let ops_url = "https://api.openproxy.space/v1/proxies?skip=0&limit=50&type=http";
    if let Ok(resp) = client.get(ops_url)
        .header("User-Agent", "Mozilla/5.0")
        .send().await
        && let Ok(text) = resp.text().await
    {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(proxies) = json.as_array() {
                for entry in proxies {
                    if let (Some(ip), Some(port)) = (
                        entry["ip"].as_str(),
                        entry["port"].as_str(),
                    ) {
                        all_results.push(format!("http://{}:{}", ip, port));
                        all_results.push(format!("socks5://{}:{}", ip, port));
                    }
                }
            }
        let mut inline = Vec::new();
        all_results.extend(extract_subscribes(&text, &mut inline));
        for p in inline { let _ = inline_tx.send(p); }
    }

    all_results.sort();
    all_results.dedup();
    log::info!("[crawl_proxy_api] Found {} proxy entries from APIs", all_results.len());
    Ok(all_results)
}
