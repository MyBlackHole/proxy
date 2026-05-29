use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::error::Result;

/// Country/region info for a proxy node
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
    pub emoji: String,
    pub is_residential: Option<bool>,
}

/// Query IP location via ip-api.com free tier (no API key needed)
pub async fn query_ip_location(
    client: &reqwest::Client,
    ip: &str,
) -> Result<GeoInfo> {
    let url = format!(
        "http://ip-api.com/json/{}?fields=country,countryCode,query",
        ip
    );
    let resp = client.get(&url).send().await?;
    let text = resp.text().await?;
    let json: serde_json::Value = serde_json::from_str(&text)?;

    let country_code = json["countryCode"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string();
    let country_name = country_code_to_chinese(&country_code);
    let emoji = country_code_to_emoji(&country_code);

    Ok(GeoInfo {
        country_code,
        country_name: country_name.to_string(),
        emoji,
        is_residential: None,
    })
}

/// Batch geo query for multiple IPs (parallel)
pub async fn batch_geo_query(
    client: &reqwest::Client,
    ips: &[String],
) -> Result<HashMap<String, GeoInfo>> {
    let sem = Arc::new(Semaphore::new(20));
    let mut handles = Vec::with_capacity(ips.len());
    for ip in ips {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let c = client.clone();
        let ip = ip.clone();
        handles.push(tokio::spawn(async move {
            let _guard = permit;
            (ip.clone(), query_ip_location(&c, &ip).await)
        }));
    }
    drop(sem);

    let mut map = HashMap::new();
    for handle in handles {
        if let Ok((ip, Ok(geo))) = handle.await {
            map.insert(ip, geo);
        }
    }
    Ok(map)
}

/// Build emoji flag from country code using Unicode Regional Indicator Symbols
pub fn country_code_to_emoji(code: &str) -> String {
    if code.len() != 2 {
        return String::new();
    }
    let code = code.to_uppercase();
    let bytes = code.as_bytes();
    let base: u32 = 0x1F1E6;
    let a = char::from_u32(base + (bytes[0] - b'A') as u32);
    let b = char::from_u32(base + (bytes[1] - b'A') as u32);
    match (a, b) {
        (Some(a), Some(b)) => format!("{}{}", a, b),
        _ => String::new(),
    }
}

/// Get Chinese name for a country code
pub fn country_code_to_chinese(code: &str) -> &'static str {
    match code.to_uppercase().as_str() {
        "CN" => "中国",
        "HK" => "香港",
        "TW" => "台湾",
        "JP" => "日本",
        "KR" => "韩国",
        "SG" => "新加坡",
        "US" => "美国",
        "GB" => "英国",
        "DE" => "德国",
        "FR" => "法国",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        "IN" => "印度",
        "RU" => "俄罗斯",
        "BR" => "巴西",
        "NL" => "荷兰",
        "SE" => "瑞典",
        "NO" => "挪威",
        "FI" => "芬兰",
        "DK" => "丹麦",
        "IT" => "意大利",
        "ES" => "西班牙",
        "PT" => "葡萄牙",
        "CH" => "瑞士",
        "AT" => "奥地利",
        "BE" => "比利时",
        "IE" => "爱尔兰",
        "NZ" => "新西兰",
        "TH" => "泰国",
        "VN" => "越南",
        "MY" => "马来西亚",
        "PH" => "菲律宾",
        "ID" => "印尼",
        "MO" => "澳门",
        "AE" => "阿联酋",
        "SA" => "沙特",
        "IL" => "以色列",
        "TR" => "土耳其",
        "ZA" => "南非",
        "AR" => "阿根廷",
        "MX" => "墨西哥",
        "PL" => "波兰",
        "CZ" => "捷克",
        "UA" => "乌克兰",
        "RO" => "罗马尼亚",
        "GR" => "希腊",
        "HU" => "匈牙利",
        "EG" => "埃及",
        "NG" => "尼日利亚",
        "KE" => "肯尼亚",
        _ => "Unknown",
    }
}

/// Regularize a proxy node name by prepending geo info
pub fn regularize_name(original: &str, geo: &GeoInfo) -> String {
    if !geo.emoji.is_empty() {
        format!("{}{} {}", geo.emoji, geo.country_name, original)
    } else {
        format!("{} {}", geo.country_name, original)
    }
}

/// Rename all proxies in a group with dedup numbering.
/// First occurrence keeps its name; subsequent duplicates get a numeric suffix.
pub fn rename_and_dedup(proxies: &mut [crate::proxy::EnrichedProxy], bits: usize) {
    let mut name_counts = HashMap::new();
    for ep in &*proxies {
        *name_counts.entry(ep.node.name().to_string()).or_insert(0usize) += 1;
    }

    let mut seen = HashMap::new();
    for ep in proxies.iter_mut() {
        let name = ep.node.name().to_string();
        if *name_counts.get(&name).unwrap_or(&0) > 1 {
            let count = seen.entry(name).or_insert(0usize);
            *count += 1;
            if *count > 1 {
                let suffix = format!(" {:0width$}", *count, width = bits);
                ep.node.set_name(format!("{}{}", ep.node.name(), suffix));
            }
        }
    }
}

/// Full regularize pipeline for EnrichedProxy: geo query, emoji prefix, latency sort
pub async fn regularize_enriched_proxies(
    client: &reqwest::Client,
    proxies: Vec<crate::proxy::EnrichedProxy>,
    config: &crate::config::RegularizeConfig,
) -> Result<Vec<crate::proxy::EnrichedProxy>> {
    if !config.locate && !config.residential {
        return Ok(proxies);
    }

    let ips: Vec<String> = proxies.iter().map(|p| p.node.host().to_string()).collect();
    let geo_map = batch_geo_query(client, &ips).await?;

    let mut enriched: Vec<crate::proxy::EnrichedProxy> = proxies
        .into_iter()
        .map(|mut ep| {
            let ip = ep.node.host().to_string();
            if let Some(geo) = geo_map.get(&ip) {
                ep.attach_geo(geo);
                let new_name = regularize_name(ep.node.name(), geo);
                ep.node.set_name(new_name);
            }
            ep
        })
        .collect();

    // Dedup numbering for same-named proxies
    rename_and_dedup(&mut enriched, config.bits);

    // Sort within each region by latency (fastest first)
    enriched.sort_by(|a, b| {
        let cc = a.country_code.cmp(&b.country_code);
        if cc == std::cmp::Ordering::Equal {
            a.latency_ms.cmp(&b.latency_ms)
        } else {
            cc
        }
    });

    Ok(enriched)
}
