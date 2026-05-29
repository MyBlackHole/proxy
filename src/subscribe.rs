use base64::Engine;
use base64::engine::general_purpose;

use crate::error::*;

#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionFormat {
    PlainText,
    Base64,
    JSON,
    YAML,
    Unknown,
}

const PROXY_SCHEMES: &[&str] = &["ss://", "ssr://", "vmess://", "trojan://", "vless://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "snell://", "socks5://", "http://", "https://", "anytls://"];

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 10 { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r')
}

pub async fn fetch_subscription(url: &str, proxy: Option<&str>) -> Result<String> {
    // Check persistent cache first
    if let Some(cached) = crate::cache::get(crate::cache::CacheKind::Subscription, url) {
        log::info!("Cache hit for subscription: {}", url);
        return Ok(cached);
    }

    let result = fetch_http(url, proxy).await;

    // On success, store in cache
    if let Ok(ref data) = result {
        crate::cache::set(crate::cache::CacheKind::Subscription, url, data);
    }
    // On failure, serve stale cache if configured
    else if crate::cache::is_enabled()
        && let Some(stale) = crate::cache::get_stale(crate::cache::CacheKind::Subscription, url) {
            log::warn!("Subscription fetch failed, serving stale cache: {}", url);
            return Ok(stale);
        }

    result
}

/// Raw HTTP fetch without caching
async fn fetch_http(url: &str, proxy: Option<&str>) -> Result<String> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = proxy {
        let p = reqwest::Proxy::all(proxy_url)
            .map_err(|e| AppError::InvalidProxy(e.to_string()))?;
        builder = builder.proxy(p);
    } else if let Ok(env_proxy) = std::env::var("ALL_PROXY").or_else(|_| std::env::var("all_proxy")) {
        log::info!("Using proxy from ALL_PROXY env: {}", env_proxy);
        if let Ok(p) = reqwest::Proxy::all(&env_proxy) {
            builder = builder.proxy(p);
        }
    } else if let Ok(env_proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
        log::info!("Using proxy from HTTPS_PROXY env: {}", env_proxy);
        if let Ok(p) = reqwest::Proxy::all(&env_proxy) {
            builder = builder.proxy(p);
        }
    }
    let client = builder.build()?;
    let resp = client.get(url).send().await?;

    // Capture Subscription-UserInfo header before consuming the response
    if let Some(header) = resp.headers().get("subscription-userinfo")
        && let Ok(val) = header.to_str()
            && !val.is_empty() {
                crate::userinfo::capture(url, val);
            }

    Ok(resp.text().await?)
}

pub fn detect_format(content: &[u8]) -> SubscriptionFormat {
    if content.is_empty() {
        return SubscriptionFormat::Unknown;
    }

    if serde_json::from_slice::<serde_json::Value>(content).is_ok() {
        return SubscriptionFormat::JSON;
    }

    if let Ok(yaml) = serde_yaml::from_slice::<serde_yaml::Value>(content)
        && (yaml.is_mapping() || yaml.is_sequence()) {
            return SubscriptionFormat::YAML;
        }

    let text = String::from_utf8_lossy(content);
    let trimmed = text.trim();

    // Try base64 on whitespace-stripped content (handles multi-line base64)
    let stripped: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if stripped.len() > 20
        && let Ok(decoded) = general_purpose::STANDARD.decode(&stripped)
            && let Ok(decoded_str) = String::from_utf8(decoded)
                && decoded_str.contains("://") {
                    return SubscriptionFormat::Base64;
                }

    // Check for per-line base64 (each line is independently base64-encoded proxy)
    if trimmed.lines().count() > 2 {
        let base64_lines = trimmed.lines()
            .filter(|l| is_likely_base64(l.trim()))
            .count();
        if base64_lines > 1 && base64_lines as f64 / trimmed.lines().count() as f64 > 0.3 {
            return SubscriptionFormat::Base64;
        }
    }

    let has_proxy_links = trimmed.lines().any(is_proxy_link);
    if has_proxy_links {
        return SubscriptionFormat::PlainText;
    }

    SubscriptionFormat::Unknown
}

pub fn decode_base64_subscription(content: &str) -> Result<String> {
    let decoded = general_purpose::STANDARD.decode(content.trim())?;
    String::from_utf8(decoded)
        .map_err(|e| AppError::InvalidConfig(format!("Invalid UTF-8: {}", e)))
}

pub fn extract_links(content: &str, format: SubscriptionFormat) -> Vec<String> {
    match format {
        SubscriptionFormat::PlainText => extract_plain_links(content),
        SubscriptionFormat::Base64 => extract_base64_links(content),
        SubscriptionFormat::JSON => extract_json_links(content),
        SubscriptionFormat::YAML => extract_yaml_links(content),
        SubscriptionFormat::Unknown => {
            let from_text = extract_plain_links(content);
            if !from_text.is_empty() {
                return from_text;
            }
            if let Ok(decoded) = decode_base64_subscription(content) {
                return extract_plain_links(&decoded);
            }
            Vec::new()
        }
    }
}

pub async fn fetch_and_parse(url: &str, proxy: Option<&str>) -> Result<Vec<String>> {
    let content = fetch_subscription(url, proxy).await?;
    let format = detect_format(content.as_bytes());
    let links = extract_links(&content, format);
    Ok(links)
}

fn is_proxy_link(s: &str) -> bool {
    PROXY_SCHEMES.iter().any(|scheme| s.trim().starts_with(scheme))
}

fn extract_plain_links(content: &str) -> Vec<String> {
    content.lines()
        .filter(|l| is_proxy_link(l))
        .map(|l| l.trim().to_string())
        .collect()
}

fn extract_base64_links(content: &str) -> Vec<String> {
    // Try decoding entire content as single base64 blob
    let stripped: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(decoded) = general_purpose::STANDARD.decode(&stripped)
        && let Ok(decoded_str) = String::from_utf8(decoded) {
            let links = extract_plain_links(&decoded_str);
            if !links.is_empty() {
                return links;
            }
        }

    // Try decoding each line independently (common subscription format)
    let mut links = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if let Ok(decoded) = general_purpose::STANDARD.decode(trimmed)
            && let Ok(text) = String::from_utf8(decoded) {
                let text = text.trim().to_string();
                if text.contains("://") {
                    links.push(text);
                }
            }
    }
    links
}

fn extract_json_links(content: &str) -> Vec<String> {
    let mut links = Vec::new();

    let from_text = extract_plain_links(content);
    links.extend(from_text);

    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(content) {
        for obj in &arr {
            if has_vmess_fields(obj)
                && let Some(link) = json_obj_to_vmess_link(obj) {
                    links.push(link);
                }
        }
    } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(content) {
        if has_vmess_fields(&obj)
            && let Some(link) = json_obj_to_vmess_link(&obj) {
                links.push(link);
            }
        if let Some(objs) = obj.as_array() {
            for item in objs {
                if has_vmess_fields(item)
                    && let Some(link) = json_obj_to_vmess_link(item) {
                        links.push(link);
                    }
            }
        }
    }

    links
}

fn extract_yaml_links(content: &str) -> Vec<String> {
    let mut links = Vec::new();

    let from_text = extract_plain_links(content);
    links.extend(from_text);

    if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content)
        && let Some(proxies) = yaml.get("proxies").and_then(|v| v.as_sequence()) {
            for proxy in proxies {
                if let Some(link) = yaml_proxy_to_url(proxy) {
                    links.push(link);
                }
            }
        }

    links
}

fn has_vmess_fields(obj: &serde_json::Value) -> bool {
    obj.get("add").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        && obj.get("id").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
}

fn json_obj_to_vmess_link(obj: &serde_json::Value) -> Option<String> {
    let ps = obj.get("ps").or_else(|| obj.get("name")).and_then(|v| v.as_str()).unwrap_or("");
    let add = obj.get("add").and_then(|v| v.as_str()).unwrap_or("");
    let port = obj.get("port").and_then(|v| {
        v.as_u64().map(|n| n.to_string())
            .or_else(|| v.as_str().map(|s| s.to_string()))
    }).unwrap_or_default();
    let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let aid = obj.get("aid").or_else(|| obj.get("alterId"))
        .and_then(|v| v.as_u64().map(|n| n.to_string()))
        .or_else(|| obj.get("aid").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "0".into());
    let net = obj.get("net").or_else(|| obj.get("network")).and_then(|v| v.as_str()).unwrap_or("tcp");
    let type_ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("none");
    let host = obj.get("host").or_else(|| obj.get("sni")).and_then(|v| v.as_str()).unwrap_or("");
    let path = obj.get("path").or_else(|| obj.get("ws-path")).and_then(|v| v.as_str()).unwrap_or("");
    let tls = obj.get("tls").and_then(|v| {
        if v.as_bool().unwrap_or(false) {
            Some("tls")
        } else {
            v.as_str().filter(|s| !s.is_empty())
        }
    }).unwrap_or("");

    let mut map = serde_json::Map::new();
    map.insert("v".into(), serde_json::Value::String("2".into()));
    map.insert("ps".into(), serde_json::Value::String(ps.into()));
    map.insert("add".into(), serde_json::Value::String(add.into()));
    map.insert("port".into(), serde_json::Value::String(port));
    map.insert("id".into(), serde_json::Value::String(id.into()));
    map.insert("aid".into(), serde_json::Value::String(aid));
    map.insert("net".into(), serde_json::Value::String(net.into()));
    map.insert("type".into(), serde_json::Value::String(type_.into()));
    map.insert("host".into(), serde_json::Value::String(host.into()));
    map.insert("path".into(), serde_json::Value::String(path.into()));
    map.insert("tls".into(), serde_json::Value::String(tls.into()));

    let vmess_obj = serde_json::Value::Object(map);
    let json_str = serde_json::to_string(&vmess_obj).ok()?;
    let encoded = general_purpose::STANDARD.encode(json_str);
    Some(format!("vmess://{}", encoded))
}

fn get_yaml_str<'a>(val: &'a serde_yaml::Value, key: &str) -> Option<&'a str> {
    val.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

fn get_yaml_port(val: &serde_yaml::Value) -> Option<String> {
    val.get("port").and_then(|v| {
        v.as_u64().map(|n| n.to_string())
            .or_else(|| v.as_str().map(|s| s.to_string()))
    })
}

fn yaml_proxy_to_url(proxy: &serde_yaml::Value) -> Option<String> {
    let type_ = get_yaml_str(proxy, "type")?;
    match type_ {
        "ss" => build_ss_url(proxy),
        "ssr" => build_ssr_url(proxy),
        "vmess" => build_vmess_from_yaml(proxy),
        "trojan" => build_trojan_url(proxy),
        "vless" => build_vless_url(proxy),
        "hysteria" | "hysteria2" | "hy2" => build_hysteria_url(proxy, type_),
        "tuic" => build_tuic_url(proxy),
        "snell" => build_snell_url(proxy),
        "socks5" => build_socks_url(proxy),
        "http" => build_http_url(proxy),
        _ => None,
    }
}

fn build_ss_url(proxy: &serde_yaml::Value) -> Option<String> {
    let method = get_yaml_str(proxy, "cipher")?;
    let password = get_yaml_str(proxy, "password")?;
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");

    let user_info = format!("{}:{}", method, password);
    let encoded = general_purpose::STANDARD.encode(user_info);
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    Some(format!("ss://{}@{}:{}#{}", encoded, server, port, name_encoded))
}

fn build_ssr_url(proxy: &serde_yaml::Value) -> Option<String> {
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let mut params: Vec<String> = Vec::new();
    let protocol = get_yaml_str(proxy, "protocol").unwrap_or("origin");
    let cipher = get_yaml_str(proxy, "cipher").unwrap_or("none");
    let obfs = get_yaml_str(proxy, "obfs").unwrap_or("plain");

    params.push(format!("protocol={}", protocol));
    params.push(format!("cipher={}", cipher));
    params.push(format!("obfs={}", obfs));

    let password = get_yaml_str(proxy, "password")?;
    let core = format!("{}:{}@{}:{}", cipher, password, server, port);
    let encoded = general_purpose::STANDARD.encode(core);
    let params_str = params.join("&");
    let param_encoded = general_purpose::STANDARD.encode(params_str);

    Some(format!("ssr://{}?{}#{}", encoded, param_encoded, name_encoded))
}

fn build_vmess_from_yaml(proxy: &serde_yaml::Value) -> Option<String> {
    let ps = get_yaml_str(proxy, "name").unwrap_or("");
    let add = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let id = get_yaml_str(proxy, "uuid")?;
    let aid = proxy.get("alterId").and_then(|v| v.as_u64()).unwrap_or(0).to_string();
    let net = get_yaml_str(proxy, "network").unwrap_or("tcp");
    let host = proxy.get("ws-headers").and_then(|h| h.get("Host")).and_then(|v| v.as_str())
        .or_else(|| get_yaml_str(proxy, "sni"))
        .unwrap_or("");
    let path = get_yaml_str(proxy, "ws-path").or_else(|| get_yaml_str(proxy, "path")).unwrap_or("");
    let tls = if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) { "tls" } else { "" };

    let mut map = serde_json::Map::new();
    map.insert("v".into(), serde_json::Value::String("2".into()));
    map.insert("ps".into(), serde_json::Value::String(ps.into()));
    map.insert("add".into(), serde_json::Value::String(add.into()));
    map.insert("port".into(), serde_json::Value::String(port));
    map.insert("id".into(), serde_json::Value::String(id.into()));
    map.insert("aid".into(), serde_json::Value::String(aid));
    map.insert("net".into(), serde_json::Value::String(net.into()));
    map.insert("type".into(), serde_json::Value::String("none".into()));
    map.insert("host".into(), serde_json::Value::String(host.into()));
    map.insert("path".into(), serde_json::Value::String(path.into()));
    map.insert("tls".into(), serde_json::Value::String(tls.into()));

    let vmess_obj = serde_json::Value::Object(map);
    let json_str = serde_json::to_string(&vmess_obj).ok()?;
    let encoded = general_purpose::STANDARD.encode(json_str);
    Some(format!("vmess://{}", encoded))
}

fn build_trojan_url(proxy: &serde_yaml::Value) -> Option<String> {
    let password = get_yaml_str(proxy, "password")?;
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    Some(format!("trojan://{}@{}:{}#{}", password, server, port, name_encoded))
}

fn build_vless_url(proxy: &serde_yaml::Value) -> Option<String> {
    let uuid = get_yaml_str(proxy, "uuid")?;
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let mut params: Vec<String> = Vec::new();
    if let Some(net) = get_yaml_str(proxy, "network") {
        params.push(format!("network={}", net));
    }
    if let Some(flow) = get_yaml_str(proxy, "flow") {
        params.push(format!("flow={}", flow));
    }
    let params_str = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    Some(format!("vless://{}@{}:{}{}#{}", uuid, server, port, params_str, name_encoded))
}

fn get_yaml_num_str(val: &serde_yaml::Value, key: &str) -> Option<String> {
    val.get(key).and_then(|v| {
        v.as_u64().map(|n| n.to_string())
            .or_else(|| v.as_str().map(|s| s.to_string()))
    })
}

fn build_hysteria_url(proxy: &serde_yaml::Value, type_: &str) -> Option<String> {
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let scheme = match type_ {
        "hysteria2" | "hy2" => "hysteria2",
        _ => "hysteria",
    };
    let auth = get_yaml_str(proxy, "auth_str").or_else(|| get_yaml_str(proxy, "password")).unwrap_or("");

    let mut params: Vec<String> = Vec::new();
    let up_val = get_yaml_str(proxy, "up").map(|s| s.to_string())
        .or_else(|| get_yaml_num_str(proxy, "up_mbps"));
    if let Some(ref up) = up_val {
        params.push(format!("up={}", up));
    }
    let down_val = get_yaml_str(proxy, "down").map(|s| s.to_string())
        .or_else(|| get_yaml_num_str(proxy, "down_mbps"));
    if let Some(ref down) = down_val {
        params.push(format!("down={}", down));
    }
    if let Some(sni) = get_yaml_str(proxy, "sni") {
        params.push(format!("sni={}", sni));
    }
    if proxy.get("skip-cert-verify").and_then(|v| v.as_bool()).unwrap_or(false) {
        params.push("insecure=1".into());
    }

    let params_str = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    Some(format!("{}://{}@{}:{}{}#{}", scheme, auth, server, port, params_str, name_encoded))
}

fn build_tuic_url(proxy: &serde_yaml::Value) -> Option<String> {
    let token = get_yaml_str(proxy, "token")?;
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    Some(format!("tuic://{}@{}:{}#{}", token, server, port, name_encoded))
}

fn build_snell_url(proxy: &serde_yaml::Value) -> Option<String> {
    let psk = get_yaml_str(proxy, "psk")?;
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let mut params: Vec<String> = Vec::new();
    if let Some(ver) = proxy.get("version").and_then(|v| v.as_u64()) {
        params.push(format!("obfs-version={}", ver));
    }
    if let Some(obfs) = get_yaml_str(proxy, "obfs") {
        params.push(format!("obfs={}", obfs));
    }
    let params_str = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    Some(format!("snell://{}@{}:{}{}#{}", psk, server, port, params_str, name_encoded))
}

fn build_socks_url(proxy: &serde_yaml::Value) -> Option<String> {
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let user = get_yaml_str(proxy, "username").unwrap_or("");
    let pass = get_yaml_str(proxy, "password").unwrap_or("");

    let auth_part = if !user.is_empty() {
        format!("{}:{}@", user, pass)
    } else {
        String::new()
    };

    Some(format!("socks5://{}{}:{}#{}", auth_part, server, port, name_encoded))
}

fn build_http_url(proxy: &serde_yaml::Value) -> Option<String> {
    let server = get_yaml_str(proxy, "server")?;
    let port = get_yaml_port(proxy)?;
    let name = get_yaml_str(proxy, "name").unwrap_or("proxy");
    let name_encoded = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);

    let user = get_yaml_str(proxy, "username").unwrap_or("");
    let pass = get_yaml_str(proxy, "password").unwrap_or("");

    let auth_part = if !user.is_empty() {
        format!("{}:{}@", user, pass)
    } else {
        String::new()
    };

    let tls = if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) { "s" } else { "" };

    Some(format!("http{}://{}{}:{}#{}", tls, auth_part, server, port, name_encoded))
}
