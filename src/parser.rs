use crate::error::{AppError, Result};
use crate::proxy::*;
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use url::Url;

/// URL-decode + replace `+` with space (form-urlencoded semantics)
fn decode_userinfo(s: &str) -> String {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.replace('+', " "))
        .unwrap_or_else(|_| s.to_string())
}

pub fn parse_proxy_url(input: &str) -> Result<ProxyNode> {
    let input = input.trim();
    if input.starts_with("vmess://") {
        parse_vmess(input)
    } else if input.starts_with("ss://") {
        parse_ss(input)
    } else if input.starts_with("trojan://") {
        parse_trojan(input)
    } else if input.starts_with("ssr://") {
        parse_ssr(input)
    } else if input.starts_with("vless://") {
        parse_vless(input)
    } else if input.starts_with("hysteria2://") || input.starts_with("hy2://") {
        parse_hysteria2(input)
    } else if input.starts_with("hysteria://") || input.starts_with("hy://") {
        parse_hysteria(input)
    } else if input.starts_with("tuic://") {
        parse_tuic(input)
    } else if input.starts_with("snell://") {
        parse_snell(input)
    } else if input.starts_with("http://") {
        parse_http(input)
    } else if input.starts_with("socks5://") {
        parse_socks5(input)
    } else if input.starts_with("anytls://") {
        parse_anytls(input)
    } else if input.starts_with("wireguard://") {
        parse_wireguard(input)
    } else {
        Err(AppError::InvalidProxy(format!(
            "unsupported protocol: {}",
            input.split("://").next().unwrap_or(input)
        )))
    }
}

fn parse_query_params(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.replace('+', " ")))
        .collect()
}

fn parse_host_port(host: &str, port_str: &str, default_port: u16) -> Result<(String, u16)> {
    if !port_str.is_empty() {
        let port: u16 = port_str
            .parse()
            .map_err(|e| {
                log::warn!("Failed to parse port '{}': {}", port_str, e);
                AppError::InvalidProxy(format!("invalid port: {}", port_str))
            })?;
        Ok((host.to_string(), port))
    } else if let Some(idx) = host.rfind(':') {
        let h = &host[..idx];
        let p: u16 = host[idx + 1..]
            .parse()
            .map_err(|e| {
                log::warn!("Failed to parse port in host '{}': {}", host, e);
                AppError::InvalidProxy(format!("invalid port in host: {}", host))
            })?;
        Ok((h.to_string(), p))
    } else {
        Ok((host.to_string(), default_port))
    }
}

fn default_name(host: &str, port: u16, proto: &str) -> String {
    format!("{}:{}-{}", host, port, proto)
}

fn b64_decode_standard(input: &str) -> Result<String> {
    let input = input.trim_end_matches('=');
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        1 => format!("{}===", input),
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE
                .decode(padded.as_bytes())
                .or_else(|_| {
                    let no_pad = input.trim_end_matches('=');
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(no_pad.as_bytes())
                        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(no_pad.as_bytes()))
                })
        })
        .map_err(AppError::Base64)?;
    String::from_utf8(bytes).map_err(|e| {
        log::warn!("Base64 decoded bytes are not valid UTF-8: {}", e);
        AppError::InvalidProxy("base64 decode not utf-8".into())
    })
}

fn b64_decode_safe(input: &str) -> Result<String> {
    let input = input.trim_end_matches('=');
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        1 => format!("{}===", input),
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    let bytes = base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()))
        .map_err(AppError::Base64)?;
    String::from_utf8(bytes).map_err(|e| {
        log::warn!("Base64 safe decoded bytes are not valid UTF-8: {}", e);
        AppError::InvalidProxy("base64 decode not utf-8".into())
    })
}

fn extract_name_from_url(url: &Url) -> Option<String> {
    url.fragment()
        .map(|s| {
            percent_encoding::percent_decode(s.as_bytes())
                .decode_utf8()
                .map(|c| c.replace('+', " "))
                .unwrap_or_else(|_| s.to_string())
        })
        .filter(|s| !s.is_empty())
}

pub fn parse_vmess(raw_url: &str) -> Result<ProxyNode> {
    let payload = raw_url.trim_start_matches("vmess://");
    let decoded = b64_decode_standard(payload)?;
    let mut vm: HashMap<String, serde_json::Value> = serde_json::from_str(&decoded)
        .map_err(|e| AppError::InvalidProxy(format!("vmess json parse error: {}", e)))?;

    let host = vm
        .remove("add")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .or_else(|| vm.remove("host").and_then(|v| v.as_str().map(|s| s.to_string())))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidProxy("vmess: missing host".into()))?;

    let port_str = vm
        .remove("port")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .or_else(|| vm.remove("PORT").and_then(|v| v.as_str().map(|s| s.to_string())))
        .unwrap_or_default();
    let port: u16 = port_str
        .parse()
        .map_err(|e| {
            log::warn!("Failed to parse vmess port '{}': {}", port_str, e);
            AppError::InvalidProxy(format!("vmess: invalid port: {}", port_str))
        })?;

    let uuid = vm
        .remove("id")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| AppError::InvalidProxy("vmess: missing id".into()))?;

    let name = vm
        .remove("ps")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_name(&host, port, "vmess"));

    let alter_id = vm
        .remove("aid")
        .or_else(|| vm.remove("alterId"))
        .and_then(|v| match v {
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::String(s) => Some(s),
            _ => None,
        });

    let cipher = vm
        .remove("scy")
        .or_else(|| vm.remove("security"))
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    let tls = vm.remove("tls").and_then(|v| match v {
        serde_json::Value::String(s) => Some(s == "tls" || s == "true"),
        serde_json::Value::Bool(b) => Some(b),
        _ => None,
    });

    let servername = vm
        .remove("sni")
        .or_else(|| vm.remove("servername"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let network = vm
        .remove("net")
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    let path_val = vm.remove("path");
    let wspath_val = vm.remove("wspath");

    let ws_path = path_val.as_ref()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .or_else(|| wspath_val.as_ref()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty()));

    let http_path = path_val.as_ref().and_then(|v| match v {
        serde_json::Value::Array(arr) => {
            let strs: Vec<String> = arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if strs.is_empty() { None } else { Some(strs) }
        }
        serde_json::Value::String(s) => {
            serde_json::from_str::<Vec<String>>(s).ok().filter(|v| !v.is_empty())
        }
        _ => None,
    });

    let host_val = vm.remove("host");
    let headers_val = vm.remove("headers");

    let ws_headers = host_val.as_ref()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .or_else(|| headers_val.as_ref()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty()))
        .map(|h| {
            let mut map = HashMap::new();
            map.insert("Host".to_string(), h);
            map
        });

    let http_headers = host_val.as_ref().and_then(|v| match v {
        serde_json::Value::Object(obj) => {
            let mut map = HashMap::new();
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    map.insert(k.clone(), s.to_string());
                }
            }
            if map.is_empty() { None } else { Some(map) }
        }
        serde_json::Value::String(s) => {
            serde_json::from_str::<HashMap<String, String>>(s).ok().filter(|m| !m.is_empty())
        }
        _ => None,
    });

    let h2_path = vm
        .remove("h2_path")
        .or_else(|| vm.remove("h2path"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let h2_host = vm
        .remove("h2_host")
        .or_else(|| vm.remove("h2host"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let grpc_service_name = vm
        .remove("service_name")
        .or_else(|| vm.remove("serviceName"))
        .or_else(|| vm.remove("grpc_service_name"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let packet_encoding = vm
        .remove("packetEncoding")
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    let skip_cert_verify = vm
        .remove("allowInsecure")
        .or_else(|| vm.remove("skip-cert-verify"))
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s == "true" || s == "1"),
            serde_json::Value::Bool(b) => Some(b),
            _ => None,
        });

    Ok(ProxyNode::VMess(VMessConfig {
        name,
        server: host,
        port,
        uuid,
        alter_id,
        cipher,
        tls,
        skip_cert_verify,
        servername,
        network,
        ws_path,
        ws_headers,
        udp: None,
        packet_encoding,
        http_path,
        http_headers,
        h2_path,
        h2_host,
        grpc_service_name,
    }))
}

pub fn parse_ss(raw_url: &str) -> Result<ProxyNode> {
    let payload = raw_url.trim_start_matches("ss://");
    let (remainder, fragment) = match payload.split_once('#') {
        Some((r, f)) => (r, Some(f.to_string())),
        None => (payload, None),
    };

    let remainder = remainder.trim_end_matches('/');
    if let Some(at_pos) = remainder.find('@') {
        let b64_part = &remainder[..at_pos];
        let host_part = &remainder[at_pos + 1..];
        let decoded = b64_decode_safe(b64_part)?;
        let sep = decoded.find(':').ok_or_else(|| {
            AppError::InvalidProxy(format!("ss: invalid credentials format: {}", decoded))
        })?;
        let method = &decoded[..sep];
        let password = &decoded[sep + 1..];
        let (server, port) = parse_host_port(host_part, "", 0)?;
        let name = fragment
            .as_ref()
            .and_then(|f| percent_encoding::percent_decode(f.as_bytes()).decode_utf8().ok())
            .map(|c| c.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default_name(&server, port, "ss"));

        Ok(ProxyNode::Shadowsocks(ShadowsocksConfig {
            name,
            server,
            port,
            cipher: method.to_string(),
            password: Some(password.to_string()),
            plugin: None,
            plugin_opts: None,
            udp: None,
        }))
    } else {
        let decoded = b64_decode_safe(remainder)?;
        if decoded.contains('@') {
            let (creds, host_part) = decoded.split_once('@').ok_or_else(|| {
                AppError::InvalidProxy(format!("ss: malformed credentials in: {}", decoded))
            })?;
            let sep = creds.find(':').ok_or_else(|| {
                AppError::InvalidProxy(format!("ss: invalid credentials: {}", decoded))
            })?;
            let method = &creds[..sep];
            let password = &creds[sep + 1..];
            let (server, port) = parse_host_port(host_part, "", 0)?;
            let name = fragment
                .as_ref()
                .and_then(|f| percent_encoding::percent_decode(f.as_bytes()).decode_utf8().ok())
                .map(|c| c.to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_name(&server, port, "ss"));

            Ok(ProxyNode::Shadowsocks(ShadowsocksConfig {
                name,
                server,
                port,
                cipher: method.to_string(),
                password: Some(password.to_string()),
                plugin: None,
                plugin_opts: None,
                udp: None,
            }))
        } else {
            let sep = decoded.rfind(':').ok_or_else(|| {
                AppError::InvalidProxy(format!("ss: invalid plain format: {}", decoded))
            })?;
            let method = &decoded[..sep];
            let rest = &decoded[sep + 1..];
            let rest_sep = rest.rfind(':').ok_or_else(|| {
                AppError::InvalidProxy(format!("ss: invalid plain format: {}", decoded))
            })?;
            let password = &rest[..rest_sep];
            let host_part = &rest[rest_sep + 1..];
            let (server, port) = parse_host_port(host_part, "", 0)?;
            let name = fragment
                .as_ref()
                .and_then(|f| percent_encoding::percent_decode(f.as_bytes()).decode_utf8().ok())
                .map(|c| c.to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_name(&server, port, "ss"));

            Ok(ProxyNode::Shadowsocks(ShadowsocksConfig {
                name,
                server,
                port,
                cipher: method.to_string(),
                password: Some(password.to_string()),
                plugin: None,
                plugin_opts: None,
                udp: None,
            }))
        }
    }
}

pub fn parse_trojan(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("trojan: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("trojan: missing host".into()))?;
    let port = url.port().unwrap_or(443);

    let password = decode_userinfo(url.username());
    if password.is_empty() {
        return Err(AppError::InvalidProxy("trojan: missing password".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "trojan"));
    let name = name.replace('+', " ");
    let sni = params
        .get("sni")
        .or(params.get("peer"))
        .or(params.get("servername"))
        .cloned();
    let alpn = params
        .get("alpn")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let udp = params.get("udp").map(|s| s == "true" || s == "1");

    let network = params.get("type").or(params.get("network")).cloned();
    let ws_path = params.get("path").or(params.get("ws-path")).cloned().filter(|s| !s.is_empty());
    let ws_headers = params.get("host").or(params.get("ws-headers")).cloned().filter(|s| !s.is_empty())
        .map(|h| {
            let mut map = HashMap::new();
            map.insert("Host".to_string(), h);
            map
        });
    let grpc_service_name = params.get("serviceName").or(params.get("service_name")).or(params.get("grpc_service_name")).cloned();

    Ok(ProxyNode::Trojan(TrojanConfig {
        name,
        server: host.to_string(),
        port,
        password,
        sni,
        alpn,
        skip_cert_verify,
        udp,
        network,
        ws_path,
        ws_headers,
        grpc_service_name,
    }))
}

pub fn parse_ssr(raw_url: &str) -> Result<ProxyNode> {
    let payload = raw_url.trim_start_matches("ssr://");
    let (b64_part, fragment) = match payload.split_once('#') {
        Some((r, f)) => (r, Some(f.to_string())),
        None => (payload, None),
    };
    let decoded = b64_decode_safe(b64_part)?;
    let (config_part, params_part) = match decoded.split_once("/?") {
        Some((c, p)) => (c, Some(p)),
        None => (decoded.as_str(), None),
    };
    let parts: Vec<&str> = config_part.split(':').collect();
    if parts.len() < 6 {
        return Err(AppError::InvalidProxy(format!(
            "ssr: expected at least 6 colon-separated parts, got {}",
            parts.len()
        )));
    }
    let server = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|e| {
            log::warn!("Failed to parse SSR port '{}': {}", parts[1], e);
            AppError::InvalidProxy(format!("ssr: invalid port: {}", parts[1]))
        })?;
    let protocol = parts[2].to_string();
    let cipher = parts[3].to_string();
    let obfs = parts[4].to_string();
    let password_b64 = parts[5];
    let password = b64_decode_safe(password_b64)?;

    let mut obfs_param = String::new();
    let mut protocol_param = String::new();
    if let Some(params_str) = params_part {
        for pair in params_str.split('&') {
            if let Some(eq) = pair.find('=') {
                let key = &pair[..eq];
                let val = &pair[eq + 1..];
                let val_decoded = percent_encoding::percent_decode(val.as_bytes())
                    .decode_utf8()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|_| val.to_string());
                match key {
                    "obfsparam" | "obfs_param" => {
                        obfs_param = b64_decode_safe(&val_decoded).unwrap_or(val_decoded)
                    }
                    "protoparam" | "protocol_param" => {
                        protocol_param = b64_decode_safe(&val_decoded).unwrap_or(val_decoded)
                    }
                    "remarks" | "group" => {}
                    _ => {}
                }
            }
        }
    }

    let name = fragment
        .as_ref()
        .and_then(|f| percent_encoding::percent_decode(f.as_bytes()).decode_utf8().ok())
        .map(|c| c.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_name(&server, port, "ssr"));

    Ok(ProxyNode::ShadowsocksR(ShadowsocksRConfig {
        name,
        server,
        port,
        password: Some(password),
        cipher,
        obfs,
        obfs_param,
        protocol,
        protocol_param,
        udp: None,
    }))
}

pub fn parse_vless(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("vless: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("vless: missing host".into()))?;
    let port = url.port().unwrap_or(443);

    let uuid = decode_userinfo(url.username());
    if uuid.is_empty() {
        return Err(AppError::InvalidProxy("vless: missing uuid".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "vless"));
    let name = name.replace('+', " ");

    let tls_val = params.get("security").or(params.get("tls"));
    let tls = tls_val.map(|s| s == "tls" || s == "reality" || s == "true");
    let servername = params.get("sni").or(params.get("servername")).cloned();
    let network = params.get("type").or(params.get("network")).cloned();
    let ws_path = params
        .get("path")
        .or(params.get("ws-path"))
        .cloned()
        .filter(|s| !s.is_empty());
    let ws_headers = params
        .get("host")
        .or(params.get("ws-headers"))
        .cloned()
        .filter(|s| !s.is_empty())
        .map(|h| {
            let mut map = HashMap::new();
            map.insert("Host".to_string(), h);
            map
        });
    let flow = params.get("flow").cloned().filter(|s| !s.is_empty());
    let packet_encoding = params
        .get("packetEncoding")
        .or(params.get("packet_encoding"))
        .cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");

    Ok(ProxyNode::VLESS(VLESSConfig {
        name,
        server: host.to_string(),
        port,
        uuid,
        tls,
        skip_cert_verify,
        servername,
        network,
        ws_path,
        ws_headers,
        flow,
        packet_encoding,
    }))
}

pub fn parse_http(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("http: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("http: missing host".into()))?;
    let port = url.port().unwrap_or(80);

    let username = decode_userinfo(url.username());
    let password = url.password().map(decode_userinfo);

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "http"));
    let name = name.replace('+', " ");
    let tls = params.get("tls").map(|s| s == "true" || s == "1");
    let sni = params.get("sni").cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");

    Ok(ProxyNode::Http(HttpConfig {
        name,
        server: host.to_string(),
        port,
        username,
        password,
        tls,
        sni,
        skip_cert_verify,
    }))
}

pub fn parse_socks5(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("socks5: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("socks5: missing host".into()))?;
    let port = url.port().unwrap_or(1080);

    let username = decode_userinfo(url.username());
    let password = url.password().map(decode_userinfo);

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "socks5"));
    let name = name.replace('+', " ");
    let tls = params.get("tls").map(|s| s == "true" || s == "1");
    let sni = params.get("sni").cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let udp = params.get("udp").map(|s| s == "true" || s == "1");

    Ok(ProxyNode::Socks5(Socks5Config {
        name,
        server: host.to_string(),
        port,
        username,
        password,
        tls,
        sni,
        skip_cert_verify,
        udp,
    }))
}

pub fn parse_hysteria(raw_url: &str) -> Result<ProxyNode> {
    let input = raw_url
        .replace("hy://", "hysteria://")
        .replace("HYSTERIA://", "hysteria://")
        .replace("Hysteria://", "hysteria://");
    let url = Url::parse(&input)
        .map_err(|e| AppError::InvalidProxy(format!("hysteria: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("hysteria: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("hysteria: missing port".into()))?;

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "hysteria"));

    let auth_str = params
        .get("auth")
        .or(params.get("auth_str"))
        .or(params.get("password"))
        .cloned()
        .unwrap_or_default();

    let protocol = params.get("protocol").cloned();
    let up = params.get("up").map(|s| s.to_string());
    let down = params.get("down").map(|s| s.to_string());
    let sni = params.get("sni").or(params.get("servername")).cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let alpn = params
        .get("alpn")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let obfs = params.get("obfs").cloned();

    Ok(ProxyNode::Hysteria(HysteriaConfig {
        name,
        server: host.to_string(),
        port,
        auth_str,
        protocol,
        up,
        down,
        sni,
        skip_cert_verify,
        alpn,
        obfs,
        up_speed: None,
        down_speed: None,
        obfs_password: None,
        ports: None,
        fingerprint: None,
        ca: None,
        ca_str: None,
        recv_window_conn: None,
        recv_window: None,
        disable_mtu_discovery: None,
        fast_open: None,
        hop_interval: None,
    }))
}

pub fn parse_hysteria2(raw_url: &str) -> Result<ProxyNode> {
    let input = raw_url
        .replace("hy2://", "hysteria2://")
        .replace("HYSTERIA2://", "hysteria2://")
        .replace("Hysteria2://", "hysteria2://");
    let url = Url::parse(&input)
        .map_err(|e| AppError::InvalidProxy(format!("hysteria2: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("hysteria2: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("hysteria2: missing port".into()))?;

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "hysteria2"));
    let name = name.replace('+', " ");

    let password = decode_userinfo(url.username());
    let password = if password.is_empty() {
        params.get("password").cloned().unwrap_or_default()
    } else {
        password
    };

    let sni = params.get("sni").or(params.get("servername")).cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let alpn = params
        .get("alpn")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let obfs = params.get("obfs").cloned();
    let obfs_password = params
        .get("obfs-password")
        .or(params.get("obfs_password"))
        .cloned();

    Ok(ProxyNode::Hysteria2(Hysteria2Config {
        name,
        server: host.to_string(),
        port,
        password,
        sni,
        skip_cert_verify,
        alpn,
        obfs,
        obfs_password,
        ports: None,
        up: None,
        down: None,
        ca: None,
        ca_str: None,
        cwnd: None,
        hop_interval: None,
    }))
}

pub fn parse_tuic(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("tuic: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("tuic: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("tuic: missing port".into()))?;

    let uuid = decode_userinfo(url.username());
    let token = decode_userinfo(url.password().unwrap_or(""));
    if uuid.is_empty() || token.is_empty() {
        return Err(AppError::InvalidProxy("tuic: missing uuid or token".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "tuic"));
    let name = name.replace('+', " ");

    let sni = params.get("sni").or(params.get("servername")).cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let alpn = params
        .get("alpn")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let udp_relay_mode = params.get("udp_relay_mode").or(params.get("mode")).cloned();
    let congestion_controller = params.get("congestion_controller").cloned();
    let ip = params.get("ip").cloned();

    Ok(ProxyNode::Tuic(TuicConfig {
        name,
        server: host.to_string(),
        port,
        token,
        ip,
        sni,
        skip_cert_verify,
        alpn,
        udp_relay_mode,
        congestion_controller,
    }))
}

pub fn parse_snell(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("snell: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("snell: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("snell: missing port".into()))?;

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "snell"));
    let name = name.replace('+', " ");

    let psk = decode_userinfo(url.username());
    let psk = if psk.is_empty() {
        params.get("psk").cloned().unwrap_or_default()
    } else {
        psk
    };

    let obfs = params.get("obfs").cloned();
    let version = params.get("version").and_then(|s| s.parse::<u8>().ok());

    Ok(ProxyNode::Snell(SnellConfig {
        name,
        server: host.to_string(),
        port,
        psk,
        obfs,
        version,
    }))
}

pub fn parse_anytls(raw_url: &str) -> Result<ProxyNode> {
    let input = raw_url
        .replace("ANYTLS://", "anytls://")
        .replace("Anytls://", "anytls://");
    let url = Url::parse(&input)
        .map_err(|e| AppError::InvalidProxy(format!("anytls: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("anytls: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("anytls: missing port".into()))?;

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "anytls"));
    let name = name.replace('+', " ");

    let password = decode_userinfo(url.username());
    let password = if password.is_empty() {
        params.get("password").cloned().unwrap_or_default()
    } else {
        password
    };

    let sni = params.get("sni").or(params.get("servername")).cloned();
    let skip_cert_verify = params
        .get("allowInsecure")
        .or(params.get("skip-cert-verify"))
        .map(|s| s == "true" || s == "1");
    let alpn = params
        .get("alpn")
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());

    Ok(ProxyNode::AnyTLS(AnyTLSConfig {
        name,
        server: host.to_string(),
        port,
        password,
        sni,
        skip_cert_verify,
        alpn,
    }))
}

pub fn parse_wireguard(raw_url: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw_url)
        .map_err(|e| AppError::InvalidProxy(format!("wireguard: invalid url: {}", e)))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::InvalidProxy("wireguard: missing host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::InvalidProxy("wireguard: missing port".into()))?;

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "wireguard"));
    let name = name.replace('+', " ");

    let private_key = params.get("private_key").cloned().unwrap_or_default();
    let public_key = params.get("public_key").cloned().unwrap_or_default();
    let ip = params.get("ip").cloned().unwrap_or_default();
    let ipv6 = params.get("ipv6").or(params.get("self_ipv6")).cloned();
    let dns = params.get("dns").cloned();
    let mtu = params.get("mtu").and_then(|s| s.parse::<u32>().ok());
    let preshared_key = params.get("preshared_key").cloned();
    let udp = params.get("udp").map(|s| s == "true" || s == "1");

    Ok(ProxyNode::WireGuard(WireGuardConfig {
        name,
        server: host.to_string(),
        port,
        private_key,
        public_key,
        ip,
        ipv6,
        dns,
        mtu,
        preshared_key,
        udp,
    }))
}

// ── Subscription Format Parsers ──────────────────────────────────────────

/// Parse Sing-box subscription format (JSON array) into proxy nodes.
///
/// Sing-box format is a JSON array of server objects, e.g.:
/// ```json
/// [{"type":"ss","tag":"my-server","server":"1.2.3.4","server_port":8388,"method":"chacha20-ietf-poly1305","password":"mypass"}]
/// ```
pub fn parse_singbox(data: &str) -> Vec<ProxyNode> {
    let Ok(json) = serde_json::from_str::<Vec<serde_json::Value>>(data) else {
        return Vec::new();
    };

    let mut proxies = Vec::new();
    for obj in &json {
        let type_ = match obj.get("type").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => continue,
        };
        let server = match obj.get("server").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let port = match obj.get("server_port").and_then(|v| v.as_u64()) {
            Some(p) => p as u16,
            None => continue,
        };
        let tag = obj
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_name(&server, port, type_));

        match type_ {
            "ss" | "shadowsocks" => {
                let method = obj
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("aes-128-gcm")
                    .to_string();
                let password = obj
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Shadowsocks(ShadowsocksConfig {
                    name: tag,
                    server,
                    port,
                    cipher: method,
                    password,
                    plugin: None,
                    plugin_opts: None,
                    udp: None,
                }));
            }
            "vmess" => {
                let uuid = obj
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let alter_id = obj
                    .get("alter_id")
                    .or_else(|| obj.get("aid"))
                    .and_then(|v| match v {
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        serde_json::Value::String(s) => Some(s.clone()),
                        _ => None,
                    });
                let cipher = obj
                    .get("security")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let tls = obj
                    .get("tls")
                    .and_then(|v| match v {
                        serde_json::Value::Bool(b) => Some(*b),
                        serde_json::Value::String(s) => Some(s == "tls" || s == "true"),
                        _ => None,
                    });
                let network = obj
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let servername = obj
                    .get("sni")
                    .or_else(|| obj.get("servername"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::VMess(VMessConfig {
                    name: tag,
                    server,
                    port,
                    uuid,
                    alter_id,
                    cipher,
                    tls,
                    skip_cert_verify: None,
                    servername,
                    network,
                    ws_path: None,
                    ws_headers: None,
                    udp: None,
                    packet_encoding: None,
                    http_path: None,
                    http_headers: None,
                    h2_path: None,
                    h2_host: None,
                    grpc_service_name: None,
                }));
            }
            "trojan" => {
                let password = obj
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let sni = obj
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Trojan(TrojanConfig {
                    name: tag,
                    server,
                    port,
                    password,
                    sni,
                    alpn: None,
                    skip_cert_verify: None,
                    udp: None,
                    network: None,
                    ws_path: None,
                    ws_headers: None,
                    grpc_service_name: None,
                }));
            }
            "vless" => {
                let uuid = obj
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tls = obj
                    .get("tls")
                    .and_then(|v| match v {
                        serde_json::Value::Bool(b) => Some(*b),
                        serde_json::Value::String(s) => Some(s == "tls" || s == "true"),
                        _ => None,
                    });
                let network = obj
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let servername = obj
                    .get("sni")
                    .or_else(|| obj.get("servername"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let flow = obj
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::VLESS(VLESSConfig {
                    name: tag,
                    server,
                    port,
                    uuid,
                    tls,
                    skip_cert_verify: None,
                    servername,
                    network,
                    ws_path: None,
                    ws_headers: None,
                    flow,
                    packet_encoding: None,
                }));
            }
            "hysteria2" | "hy2" => {
                let password = obj
                    .get("password")
                    .or_else(|| obj.get("auth"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let sni = obj
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let obfs = obj
                    .get("obfs")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let obfs_password = obj
                    .get("obfs_password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Hysteria2(Hysteria2Config {
                    name: tag,
                    server,
                    port,
                    password,
                    sni,
                    skip_cert_verify: None,
                    alpn: None,
                    obfs,
                    obfs_password,
                    ports: None,
                    up: None,
                    down: None,
                    ca: None,
                    ca_str: None,
                    cwnd: None,
                    hop_interval: None,
                }));
            }
            "hysteria" | "hy" => {
                let auth_str = obj
                    .get("auth")
                    .or_else(|| obj.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let up = obj
                    .get("up")
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string());
                let down = obj
                    .get("down")
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string());
                let sni = obj
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let obfs = obj
                    .get("obfs")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Hysteria(HysteriaConfig {
                    name: tag,
                    server,
                    port,
                    auth_str,
                    protocol: None,
                    up,
                    down,
                    sni,
                    skip_cert_verify: None,
                    alpn: None,
                    obfs,
                    up_speed: None,
                    down_speed: None,
                    obfs_password: None,
                    ports: None,
                    fingerprint: None,
                    ca: None,
                    ca_str: None,
                    recv_window_conn: None,
                    recv_window: None,
                    disable_mtu_discovery: None,
                    fast_open: None,
                    hop_interval: None,
                }));
            }
            "tuic" => {
                let token = obj
                    .get("token")
                    .or_else(|| obj.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let sni = obj
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Tuic(TuicConfig {
                    name: tag,
                    server,
                    port,
                    token,
                    ip: None,
                    sni,
                    skip_cert_verify: None,
                    alpn: None,
                    udp_relay_mode: None,
                    congestion_controller: None,
                }));
            }
            "http" => {
                let username = obj
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let password = obj
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Http(HttpConfig {
                    name: tag,
                    server,
                    port,
                    username,
                    password,
                    tls: None,
                    sni: None,
                    skip_cert_verify: None,
                }));
            }
            "socks5" => {
                let username = obj
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let password = obj
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                proxies.push(ProxyNode::Socks5(Socks5Config {
                    name: tag,
                    server,
                    port,
                    username,
                    password,
                    tls: None,
                    sni: None,
                    skip_cert_verify: None,
                    udp: None,
                }));
            }
            "wireguard" => {
                let private_key = obj
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let public_key = obj
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ip = obj
                    .get("self_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ipv6 = obj
                    .get("self_ipv6")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let dns = obj
                    .get("dns")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let mtu = obj
                    .get("mtu")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                let preshared_key = obj
                    .get("preshared_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let udp = obj
                    .get("udp")
                    .and_then(|v| match v {
                        serde_json::Value::Bool(b) => Some(*b),
                        _ => None,
                    });
                proxies.push(ProxyNode::WireGuard(WireGuardConfig {
                    name: tag,
                    server,
                    port,
                    private_key,
                    public_key,
                    ip,
                    ipv6,
                    dns,
                    mtu,
                    preshared_key,
                    udp,
                }));
            }
            _ => {}
        }
    }
    proxies
}

/// Parse a single Quantumult X style proxy line into a ProxyNode.
///
/// Format: `protocol=host:port, key=value, key=value, ...`
/// Supported protocols: shadowsocks, vmess, trojan
fn parse_quantumult_line(line: &str) -> Option<ProxyNode> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }

    // Split on first `=` to get protocol and the rest
    let eq_pos = line.find('=')?;
    let protocol = line[..eq_pos].trim().to_lowercase();
    let rest = line[eq_pos + 1..].trim();

    // Rest format: `host:port, key=value, key=value, ...`
    // Split by comma, first part is host:port
    let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return None;
    }

    let host_port = parts[0];
    let (server, port) = parse_host_port_simple(host_port)?;

    // Parse key=value pairs
    let mut params = std::collections::HashMap::new();
    for part in &parts[1..] {
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim().to_lowercase();
            let val = part[eq + 1..].trim().to_string();
            params.insert(key, val);
        }
    }

    let tag = params
        .remove("tag")
        .or_else(|| params.remove("remarks"))
        .or_else(|| params.remove("name"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_name(&server, port, &protocol));

    match protocol.as_str() {
        "shadowsocks" | "ss" => {
            let method = params
                .remove("method")
                .or_else(|| params.remove("encrypt-method"))
                .or_else(|| params.remove("cipher"))
                .unwrap_or_else(|| "aes-128-gcm".to_string());
            let password = params.remove("password");
            let obfs = params.remove("obfs");
            let obfs_param = params.remove("obfs-host").or_else(|| params.remove("obfs-param"));
            let plugin = obfs.map(|o| format!("obfs-{}", o));
            let plugin_opts = obfs_param.map(|p| format!("obfs-host={}", p));

            Some(ProxyNode::Shadowsocks(ShadowsocksConfig {
                name: tag,
                server,
                port,
                cipher: method,
                password,
                plugin,
                plugin_opts,
                udp: None,
            }))
        }
        "vmess" => {
            let uuid = params
                .remove("password")
                .or_else(|| params.remove("uuid"))
                .unwrap_or_default();
            let cipher = params.remove("method").or_else(|| params.remove("cipher"));
            let tls_val = params
                .remove("over-tls")
                .or_else(|| params.remove("tls"))
                .map(|s| s == "true" || s == "1");
            let servername = params
                .remove("tls-host")
                .or_else(|| params.remove("sni"))
                .or_else(|| params.remove("servername"));
            let network = params.remove("network").or_else(|| {
                if params.remove("ws").map(|s| s == "true").unwrap_or(false) {
                    Some("ws".to_string())
                } else {
                    None
                }
            });
            let ws_path = params.remove("ws-path").or_else(|| params.remove("path"));

            Some(ProxyNode::VMess(VMessConfig {
                name: tag,
                server,
                port,
                uuid,
                alter_id: None,
                cipher,
                tls: tls_val,
                skip_cert_verify: None,
                servername,
                network,
                ws_path,
                ws_headers: None,
                udp: None,
                packet_encoding: None,
                http_path: None,
                http_headers: None,
                h2_path: None,
                h2_host: None,
                grpc_service_name: None,
            }))
        }
        "trojan" => {
            let password = params
                .remove("password")
                .unwrap_or_default();
            let sni = params
                .remove("sni")
                .or_else(|| params.remove("tls-host"))
                .or_else(|| params.remove("servername"));

            Some(ProxyNode::Trojan(TrojanConfig {
                name: tag,
                server,
                port,
                password,
                sni,
                alpn: None,
                skip_cert_verify: None,
                udp: None,
                network: None,
                ws_path: None,
                ws_headers: None,
                grpc_service_name: None,
            }))
        }
        _ => None,
    }
}

/// Parse host:port string into (String, u16)
fn parse_host_port_simple(input: &str) -> Option<(String, u16)> {
    let input = input.trim();
    if let Some(colon) = input.rfind(':') {
        let host = input[..colon].to_string();
        let port: u16 = input[colon + 1..].parse().ok()?;
        Some((host, port))
    } else {
        None
    }
}

/// Parse Quantumult X subscription format into proxy nodes.
///
/// Quantumult X format is line-based:
/// - `shadowsocks=host:port, method=chacha20, password=xxx, tag=my-server`
/// - `vmess=host:port, method=chacha20-ietf-poly1305, password=xxx, tag=my-server`
/// - `trojan=host:port, password=xxx, over-tls=true, tag=my-server`
///
/// Also handles base64-encoded quantumult subscriptions (each line is base64).
pub fn parse_quantumult(data: &str) -> Vec<ProxyNode> {
    // Collect lines, trying the standard format first
    let mut proxies: Vec<ProxyNode> = Vec::new();

    for line in data.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try direct parse
        if let Some(node) = parse_quantumult_line(trimmed) {
            proxies.push(node);
            continue;
        }

        // Try base64 decode on the line (common in Quantumult X subscriptions)
        if is_likely_base64_line(trimmed)
            && let Ok(decoded) = b64_decode_standard(trimmed)
                && let Some(node) = parse_quantumult_line(decoded.trim()) {
                    proxies.push(node);
                }
    }

    proxies
}

/// Check if a string looks like a base64-encoded line
fn is_likely_base64_line(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 10 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r')
}

/// Parse Surfboard subscription format into proxy nodes.
///
/// Surfboard format has a `[Proxy]` section with lines like:
/// ```text
/// [Proxy]
/// ss = ss, 1.2.3.4, 8388, encrypt-method=chacha20-ietf-poly1305, password=mypass, udp=true
/// vmess = vmess, 1.2.3.4, 443, username=xxx, ws=true, ws-path=/path
/// trojan = trojan, 1.2.3.4, 443, password=xxx, udp=true
/// ```
///
/// Format per line: `name = type, server, port, key=value, key=value, ...`
pub fn parse_surfboard(data: &str) -> Vec<ProxyNode> {
    let mut proxies = Vec::new();
    let mut in_proxy_section = false;

    for line in data.lines() {
        let trimmed = line.trim();

        // Section headers
        if trimmed.starts_with('[') {
            in_proxy_section = trimmed.eq_ignore_ascii_case("[Proxy]");
            continue;
        }

        if !in_proxy_section || trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';')
        {
            continue;
        }

        if let Some(node) = parse_surfboard_line(trimmed) {
            proxies.push(node);
        }
    }

    proxies
}

/// Parse a single Surfboard proxy line.
///
/// Format: `name = type, server, port, key=value, ...`
fn parse_surfboard_line(line: &str) -> Option<ProxyNode> {
    let line = line.trim();

    // Split on first `=`
    let eq_pos = line.find('=')?;
    let name = line[..eq_pos].trim().to_string();
    let rest = line[eq_pos + 1..].trim();

    // Split remaining by comma
    let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
    if parts.len() < 3 {
        return None;
    }

    let proxy_type = parts[0].to_lowercase();
    let server = parts[1].to_string();
    let port: u16 = parts[2].parse().ok()?;

    // Parse key=value pairs from remaining parts
    let mut params = std::collections::HashMap::new();
    for part in &parts[3..] {
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim().to_lowercase();
            let val = part[eq + 1..].trim().to_string();
            params.insert(key, val);
        }
    }

    match proxy_type.as_str() {
        "ss" | "shadowsocks" => {
            let cipher = params
                .remove("encrypt-method")
                .or_else(|| params.remove("method"))
                .or_else(|| params.remove("cipher"))
                .unwrap_or_else(|| "aes-128-gcm".to_string());
            let password = params.remove("password");
            let udp = params
                .remove("udp")
                .map(|s| s == "true" || s == "1");

            Some(ProxyNode::Shadowsocks(ShadowsocksConfig {
                name,
                server,
                port,
                cipher,
                password,
                plugin: None,
                plugin_opts: None,
                udp,
            }))
        }
        "vmess" => {
            let uuid = params
                .remove("username")
                .or_else(|| params.remove("uuid"))
                .unwrap_or_default();
            let cipher = params
                .remove("encrypt-method")
                .or_else(|| params.remove("method"))
                .or_else(|| params.remove("cipher"));
            let tls = params
                .remove("tls")
                .map(|s| s == "true" || s == "1");
            let servername = params
                .remove("sni")
                .or_else(|| params.remove("servername"));
            let network = params.remove("network").or_else(|| {
                if params.remove("ws").map(|s| s == "true").unwrap_or(false) {
                    Some("ws".to_string())
                } else {
                    None
                }
            });
            let ws_path = params
                .remove("ws-path")
                .or_else(|| params.remove("path"));

            Some(ProxyNode::VMess(VMessConfig {
                name,
                server,
                port,
                uuid,
                alter_id: None,
                cipher,
                tls,
                skip_cert_verify: None,
                servername,
                network,
                ws_path,
                ws_headers: None,
                udp: None,
                packet_encoding: None,
                http_path: None,
                http_headers: None,
                h2_path: None,
                h2_host: None,
                grpc_service_name: None,
            }))
        }
        "trojan" => {
            let password = params
                .remove("password")
                .unwrap_or_default();
            let sni = params
                .remove("sni")
                .or_else(|| params.remove("servername"));
            let udp = params
                .remove("udp")
                .map(|s| s == "true" || s == "1");
            let skip_cert_verify = params
                .remove("skip-cert-verify")
                .map(|s| s == "true" || s == "1");

            Some(ProxyNode::Trojan(TrojanConfig {
                name,
                server,
                port,
                password,
                sni,
                alpn: None,
                skip_cert_verify,
                udp,
                network: None,
                ws_path: None,
                ws_headers: None,
                grpc_service_name: None,
            }))
        }
        "vless" => {
            let uuid = params
                .remove("uuid")
                .or_else(|| params.remove("username"))
                .unwrap_or_default();
            let tls = params
                .remove("tls")
                .map(|s| s == "true" || s == "1");
            let servername = params
                .remove("sni")
                .or_else(|| params.remove("servername"));
            let network = params.remove("network").or_else(|| {
                if params.remove("ws").map(|s| s == "true").unwrap_or(false) {
                    Some("ws".to_string())
                } else {
                    None
                }
            });
            let ws_path = params
                .remove("ws-path")
                .or_else(|| params.remove("path"));
            let flow = params.remove("flow");

            Some(ProxyNode::VLESS(VLESSConfig {
                name,
                server,
                port,
                uuid,
                tls,
                skip_cert_verify: None,
                servername,
                network,
                ws_path,
                ws_headers: None,
                flow,
                packet_encoding: None,
            }))
        }
        "hysteria2" | "hy2" => {
            let password = params
                .remove("password")
                .unwrap_or_default();
            let sni = params
                .remove("sni")
                .or_else(|| params.remove("servername"));
            let obfs = params.remove("obfs");

            Some(ProxyNode::Hysteria2(Hysteria2Config {
                name,
                server,
                port,
                password,
                sni,
                skip_cert_verify: None,
                alpn: None,
                obfs,
                obfs_password: None,
                ports: None,
                up: None,
                down: None,
                ca: None,
                ca_str: None,
                cwnd: None,
                hop_interval: None,
            }))
        }
        "http" => {
            let username = params
                .remove("username")
                .unwrap_or_default();
            let password = params.remove("password");
            let tls = params
                .remove("tls")
                .map(|s| s == "true" || s == "1");

            Some(ProxyNode::Http(HttpConfig {
                name,
                server,
                port,
                username,
                password,
                tls,
                sni: None,
                skip_cert_verify: None,
            }))
        }
        "socks5" => {
            let username = params
                .remove("username")
                .unwrap_or_default();
            let password = params.remove("password");
            let tls = params
                .remove("tls")
                .map(|s| s == "true" || s == "1");
            let udp = params
                .remove("udp")
                .map(|s| s == "true" || s == "1");

            Some(ProxyNode::Socks5(Socks5Config {
                name,
                server,
                port,
                username,
                password,
                tls,
                sni: None,
                skip_cert_verify: None,
                udp,
            }))
        }
        _ => None,
    }
}

/// Parse subscription text by detecting format and dispatching to the appropriate parser.
///
/// Detection order:
/// 1. Sing-box JSON array (starts with `[`, contains `"type"` + `"server"`)
/// 2. Surfboard (contains `[Proxy]` section)
/// 3. Quantumult X (lines matching `protocol=host:port,` pattern)
///
/// Returns all parsed proxies, or empty Vec if no format matches.
/// The caller should fall through to standard URL-based parsing if empty.
pub fn parse_subscribe(text: &str) -> Vec<ProxyNode> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // 1. Sing-box detection: JSON array with proxy-like objects
    if trimmed.starts_with('[')
        && let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed)
            && v.iter().any(|o| {
                o.get("type")
                    .and_then(|t| t.as_str())
                    .is_some()
                    && o.get("server").and_then(|s| s.as_str()).is_some()
            }) {
                let proxies = parse_singbox(trimmed);
                if !proxies.is_empty() {
                    return proxies;
                }
            }

    // 2. Surfboard detection: contains [Proxy] section
    if trimmed.contains("[Proxy]") || trimmed.contains("[proxy]") {
        let proxies = parse_surfboard(trimmed);
        if !proxies.is_empty() {
            return proxies;
        }
    }

    // 3. Quantumult X detection: lines protocol=host:port, ...
    if trimmed.lines().any(|l| {
        let l = l.trim();
        !l.is_empty()
            && !l.starts_with('#')
            && !l.starts_with("//")
            && (l.starts_with("shadowsocks=")
                || l.starts_with("ss=")
                || l.starts_with("vmess=")
                || l.starts_with("trojan="))
    }) {
        let proxies = parse_quantumult(trimmed);
        if !proxies.is_empty() {
            return proxies;
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vmess() {
        let link = "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLWhlcmUiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwidGxzIjoidGxzIiwicHMiOiJ0ZXN0LXZtZXNzIn0=";
        let node = parse_vmess(link).unwrap();
        assert_eq!(node.name(), "test-vmess");
        assert_eq!(node.host(), "127.0.0.1");
        assert_eq!(node.port(), 443);
        if let ProxyNode::VMess(c) = node {
            assert_eq!(c.uuid, "uuid-here");
            assert_eq!(c.alter_id, Some("0".into()));
            assert_eq!(c.cipher, Some("auto".into()));
            assert_eq!(c.tls, Some(true));
        } else {
            panic!("expected VMess");
        }
    }

    #[test]
    fn test_parse_ss_standard() {
        let link = "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=";
        let node = parse_ss(link).unwrap();
        assert_eq!(node.port(), 8388);
        if let ProxyNode::Shadowsocks(c) = node {
            assert_eq!(c.cipher, "aes-128-gcm");
            assert_eq!(c.password, Some("password".into()));
            assert_eq!(c.server, "127.0.0.1");
        } else {
            panic!("expected Shadowsocks");
        }
    }

    #[test]
    fn test_parse_ss_with_name() {
        let link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=#my-server";
        let node = parse_ss(link).unwrap();
        assert_eq!(node.name(), "my-server");
    }

    #[test]
    fn test_parse_trojan() {
        let link = "trojan://password123@example.com:443?sni=example.com&allowInsecure=true#my-trojan";
        let node = parse_trojan(link).unwrap();
        assert_eq!(node.name(), "my-trojan");
        assert_eq!(node.host(), "example.com");
        assert_eq!(node.port(), 443);
        if let ProxyNode::Trojan(c) = node {
            assert_eq!(c.password, "password123");
            assert_eq!(c.sni, Some("example.com".into()));
            assert_eq!(c.skip_cert_verify, Some(true));
        } else {
            panic!("expected Trojan");
        }
    }

    #[test]
    fn test_parse_trojan_no_query() {
        let link = "trojan://password@host.com:443";
        let node = parse_trojan(link).unwrap();
        assert_eq!(node.host(), "host.com");
    }

    #[test]
    fn test_parse_ssr() {
        let b64_config = base64::engine::general_purpose::URL_SAFE.encode("127.0.0.1:1234:origin:aes-256-cfb:plain:aHR0cA");
        let link = format!("ssr://{}", b64_config);
        let node = parse_ssr(&link).unwrap();
        assert_eq!(node.host(), "127.0.0.1");
        assert_eq!(node.port(), 1234);
        if let ProxyNode::ShadowsocksR(c) = node {
            assert_eq!(c.cipher, "aes-256-cfb");
            assert_eq!(c.protocol, "origin");
            assert_eq!(c.obfs, "plain");
            assert_eq!(c.password, Some("http".into()));
        } else {
            panic!("expected ShadowsocksR");
        }
    }

    #[test]
    fn test_parse_vless() {
        let link = "vless://uuid123@example.com:443?security=tls&sni=example.com&flow=xtls-rprx-vision#my-vless";
        let node = parse_vless(link).unwrap();
        assert_eq!(node.name(), "my-vless");
        if let ProxyNode::VLESS(c) = node {
            assert_eq!(c.uuid, "uuid123");
            assert_eq!(c.tls, Some(true));
            assert_eq!(c.servername, Some("example.com".into()));
            assert_eq!(c.flow, Some("xtls-rprx-vision".into()));
        } else {
            panic!("expected VLESS");
        }
    }

    #[test]
    fn test_parse_http() {
        let link = "http://user:pass@proxy.com:8080#my-http";
        let node = parse_http(link).unwrap();
        assert_eq!(node.name(), "my-http");
        if let ProxyNode::Http(c) = node {
            assert_eq!(c.username, "user");
            assert_eq!(c.password, Some("pass".into()));
            assert_eq!(c.server, "proxy.com");
            assert_eq!(c.port, 8080);
        } else {
            panic!("expected Http");
        }
    }

    #[test]
    fn test_parse_socks5() {
        let link = "socks5://user:pass@socks.com:1080#my-socks";
        let node = parse_socks5(link).unwrap();
        assert_eq!(node.name(), "my-socks");
        if let ProxyNode::Socks5(c) = node {
            assert_eq!(c.username, "user");
            assert_eq!(c.server, "socks.com");
        } else {
            panic!("expected Socks5");
        }
    }

    #[test]
    fn test_parse_hysteria() {
        let link = "hysteria://hyst.com:443?auth=secret123&up=50&down=100&sni=hyst.com#my-hy";
        let node = parse_hysteria(link).unwrap();
        assert_eq!(node.name(), "my-hy");
        if let ProxyNode::Hysteria(c) = node {
            assert_eq!(c.auth_str, "secret123");
            assert_eq!(c.up, Some("50".into()));
            assert_eq!(c.down, Some("100".into()));
        } else {
            panic!("expected Hysteria");
        }
    }

    #[test]
    fn test_parse_hysteria2() {
        let link = "hysteria2://hy2.com:443?password=secret&sni=hy2.com#my-hy2";
        let node = parse_hysteria2(link).unwrap();
        assert_eq!(node.name(), "my-hy2");
        if let ProxyNode::Hysteria2(c) = node {
            assert_eq!(c.password, "secret");
        } else {
            panic!("expected Hysteria2");
        }
    }

    #[test]
    fn test_parse_tuic() {
        let link = "tuic://uuid:token@tuic.com:14443?sni=tuic.com#my-tuic";
        let node = parse_tuic(link).unwrap();
        assert_eq!(node.name(), "my-tuic");
        if let ProxyNode::Tuic(c) = node {
            assert_eq!(c.token, "token");
        } else {
            panic!("expected Tuic");
        }
    }

    #[test]
    fn test_parse_snell() {
        let link = "snell://snell.com:12345?psk=mykey&obfs=http&version=2#my-snell";
        let node = parse_snell(link).unwrap();
        assert_eq!(node.name(), "my-snell");
        if let ProxyNode::Snell(c) = node {
            assert_eq!(c.psk, "mykey");
            assert_eq!(c.obfs, Some("http".into()));
            assert_eq!(c.version, Some(2));
        } else {
            panic!("expected Snell");
        }
    }

    #[test]
    fn test_parse_anytls() {
        let link = "anytls://any.com:8443?password=secret123&sni=any.com#my-any";
        let node = parse_anytls(link).unwrap();
        assert_eq!(node.name(), "my-any");
        if let ProxyNode::AnyTLS(c) = node {
            assert_eq!(c.password, "secret123");
        } else {
            panic!("expected AnyTLS");
        }
    }

    #[test]
    fn test_parse_proxy_url_dispatcher() {
        let vmess =
            parse_proxy_url("vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkIn0=")
                .unwrap();
        assert_eq!(vmess.host(), "127.0.0.1");

        let ss = parse_proxy_url("ss://YWVzLTEyOC1nY206cGFzc0AxMjcuMC4wLjE6ODA=").unwrap();
        assert_eq!(ss.port(), 80);

        let trojan = parse_proxy_url("trojan://pass@host.com:443").unwrap();
        assert_eq!(trojan.host(), "host.com");
    }

    #[test]
    fn test_parse_unsupported_protocol() {
        let result = parse_proxy_url("unknown://something");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hy2_alias() {
        let link = "hy2://hy2.com:443?password=secret#hy2-alias";
        let node = parse_proxy_url(link).unwrap();
        assert_eq!(node.name(), "hy2-alias");
        assert!(matches!(node, ProxyNode::Hysteria2(_)));
    }

    #[test]
    fn test_parse_ss_sip008_style() {
        let link = "ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388";
        let node = parse_ss(link).unwrap();
        if let ProxyNode::Shadowsocks(c) = node {
            assert_eq!(c.cipher, "aes-128-gcm");
            assert_eq!(c.password, Some("pass".into()));
            assert_eq!(c.server, "127.0.0.1");
            assert_eq!(c.port, 8388);
        } else {
            panic!("expected Shadowsocks");
        }
    }

    #[test]
    fn test_parse_vmess_with_packet_encoding() {
        let link = "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkIiwicGFja2V0RW5jb2RpbmciOiJwYWNrZXQtZW5jb2RpbmctdGVzdCJ9";
        let node = parse_vmess(link).unwrap();
        if let ProxyNode::VMess(c) = node {
            assert_eq!(c.packet_encoding, Some("packet-encoding-test".into()));
        } else {
            panic!("expected VMess");
        }
    }

    #[test]
    fn test_vless_name_plus_to_space() {
        let node = parse_vless("vless://uuid@1.2.3.4:443?security=tls&sni=test.com&type=ws&path=/test#United+States").unwrap();
        assert!(!node.name().contains('+'), "VLESS name should not contain '+': {}", node.name());
        assert!(node.name().contains("United States"), "VLESS name should have space: {}", node.name());
    }

    #[test]
    fn test_trojan_name_plus_to_space() {
        let node = parse_trojan("trojan://password@1.2.3.4:443?security=tls&sni=test.com#Hong+Kong").unwrap();
        assert!(!node.name().contains('+'), "Trojan name should not contain '+': {}", node.name());
        assert!(node.name().contains("Hong Kong"), "Trojan name should have space: {}", node.name());
    }

    #[test]
    fn test_trojan_password_percent_decoded() {
        let node = parse_trojan("trojan://my%2Fpassword%23test@1.2.3.4:443?security=tls#test").unwrap();
        if let ProxyNode::Trojan(c) = node {
            assert_eq!(c.password, "my/password#test", "Trojan password should be percent-decoded: {}", c.password);
        } else {
            panic!("expected Trojan");
        }
    }

    #[test]
    fn test_tuic_name_plus_to_space() {
        let node = parse_tuic("tuic://uuid:token@1.2.3.4:443?sni=test.com#South+Korea").unwrap();
        assert!(!node.name().contains('+'), "TUIC name should not contain '+': {}", node.name());
        assert!(node.name().contains("South Korea"), "TUIC name should have space: {}", node.name());
    }

    #[test]
    fn test_parse_singbox_ss() {
        let data = r#"[{"type":"ss","tag":"sg-01","server":"1.2.3.4","server_port":8388,"method":"chacha20-ietf-poly1305","password":"mypass"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Shadowsocks(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.port, 8388);
            assert_eq!(cfg.cipher, "chacha20-ietf-poly1305");
            assert_eq!(cfg.password.as_deref(), Some("mypass"));
            assert_eq!(cfg.name, "sg-01");
        } else {
            panic!("expected Shadowsocks variant");
        }
    }

    #[test]
    fn test_parse_singbox_vmess() {
        let data = r#"[{"type":"vmess","tag":"vmess-01","server":"1.2.3.4","server_port":443,"uuid":"abc-def-ghi","security":"auto","tls":true,"network":"ws"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::VMess(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.uuid, "abc-def-ghi");
            assert_eq!(cfg.tls, Some(true));
            assert_eq!(cfg.network.as_deref(), Some("ws"));
        } else {
            panic!("expected VMess variant");
        }
    }

    #[test]
    fn test_parse_singbox_trojan() {
        let data = r#"[{"type":"trojan","tag":"tro-jp","server":"5.6.7.8","server_port":443,"password":"pass123","sni":"example.com"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Trojan(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "5.6.7.8");
            assert_eq!(cfg.password, "pass123");
            assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        } else {
            panic!("expected Trojan variant");
        }
    }

    #[test]
    fn test_parse_singbox_hysteria2() {
        let data = r#"[{"type":"hysteria2","tag":"hy2-01","server":"1.2.3.4","server_port":8443,"password":"auth123","sni":"test.com"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Hysteria2(cfg) = &proxies[0] {
            assert_eq!(cfg.password, "auth123");
            assert_eq!(cfg.sni.as_deref(), Some("test.com"));
        } else {
            panic!("expected Hysteria2 variant");
        }
    }

    #[test]
    fn test_parse_singbox_vless() {
        let data = r#"[{"type":"vless","tag":"vl-01","server":"1.2.3.4","server_port":443,"uuid":"abc-123","tls":true,"flow":"xtls-rprx-vision","network":"tcp"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::VLESS(cfg) = &proxies[0] {
            assert_eq!(cfg.uuid, "abc-123");
            assert_eq!(cfg.flow.as_deref(), Some("xtls-rprx-vision"));
        } else {
            panic!("expected VLESS variant");
        }
    }

    #[test]
    fn test_parse_singbox_tuic() {
        let data = r#"[{"type":"tuic","tag":"tu-01","server":"1.2.3.4","server_port":443,"token":"mytoken","sni":"example.com"}]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Tuic(cfg) = &proxies[0] {
            assert_eq!(cfg.token, "mytoken");
            assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        } else {
            panic!("expected Tuic variant");
        }
    }

    #[test]
    fn test_parse_singbox_invalid_json() {
        let proxies = parse_singbox("not json");
        assert!(proxies.is_empty(), "invalid JSON should return empty");
    }

    #[test]
    fn test_parse_singbox_empty_array() {
        let proxies = parse_singbox("[]");
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_parse_singbox_multiple_proxies() {
        let data = r#"[
            {"type":"ss","tag":"s1","server":"1.1.1.1","server_port":1111,"method":"aes","password":"p1"},
            {"type":"trojan","tag":"t1","server":"2.2.2.2","server_port":2222,"password":"p2"}
        ]"#;
        let proxies = parse_singbox(data);
        assert_eq!(proxies.len(), 2, "should parse both entries");
    }

    #[test]
    fn test_parse_quantumult_shadowsocks() {
        let data = "shadowsocks=1.2.3.4:8443, method=chacha20, password=pass123, tag=my-ss";
        let proxies = parse_quantumult(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Shadowsocks(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.port, 8443);
            assert_eq!(cfg.cipher, "chacha20");
            assert_eq!(cfg.password.as_deref(), Some("pass123"));
            assert_eq!(cfg.name, "my-ss");
        } else {
            panic!("expected Shadowsocks variant");
        }
    }

    #[test]
    fn test_parse_quantumult_vmess() {
        let data = r#"vmess=1.2.3.4:443, method=aes-128-gcm, password=uuid-here, tag=my-vm"#;
        let proxies = parse_quantumult(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::VMess(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.port, 443);
            assert_eq!(cfg.uuid, "uuid-here");
        } else {
            panic!("expected VMess variant");
        }
    }

    #[test]
    fn test_parse_quantumult_trojan() {
        let data = "trojan=1.2.3.4:443, password=pass456, over-tls=true, tag=my-tj";
        let proxies = parse_quantumult(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Trojan(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.password, "pass456");
        } else {
            panic!("expected Trojan variant");
        }
    }

    #[test]
    fn test_parse_quantumult_no_tag() {
        let data = "shadowsocks=1.2.3.4:8388, method=aes-256-gcm, password=p123";
        let proxies = parse_quantumult(data);
        assert_eq!(proxies.len(), 1, "should parse even without tag");
    }

    #[test]
    fn test_parse_quantumult_empty() {
        let proxies = parse_quantumult("");
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_parse_surfboard_ss() {
        let data = "\
[Proxy]
ss = ss, 1.2.3.4, 8388, encrypt-method=chacha20-ietf-poly1305, password=pass123, udp=true";
        let proxies = parse_surfboard(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Shadowsocks(cfg) = &proxies[0] {
            assert_eq!(cfg.server, "1.2.3.4");
            assert_eq!(cfg.port, 8388);
            assert_eq!(cfg.cipher, "chacha20-ietf-poly1305");
            assert_eq!(cfg.password.as_deref(), Some("pass123"));
        } else {
            panic!("expected Shadowsocks variant");
        }
    }

    #[test]
    fn test_parse_surfboard_vmess() {
        let data = "\
[Proxy]
vmess = vmess, 1.2.3.4, 443, username=abc-123, ws=true, ws-path=/api, tls=true";
        let proxies = parse_surfboard(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::VMess(cfg) = &proxies[0] {
            assert_eq!(cfg.uuid, "abc-123");
            assert!(cfg.tls.unwrap_or(false), "tls should be true");
        } else {
            panic!("expected VMess variant");
        }
    }

    #[test]
    fn test_parse_surfboard_trojan() {
        let data = "\
[Proxy]
trojan = trojan, 1.2.3.4, 443, password=xyz789, sni=example.com, udp=true";
        let proxies = parse_surfboard(data);
        assert_eq!(proxies.len(), 1);
        if let ProxyNode::Trojan(cfg) = &proxies[0] {
            assert_eq!(cfg.password, "xyz789");
            assert_eq!(cfg.sni.as_deref(), Some("example.com"));
        } else {
            panic!("expected Trojan variant");
        }
    }

    #[test]
    fn test_parse_surfboard_no_section() {
        let proxies = parse_surfboard("just some text without proxy section");
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_parse_surfboard_multiple_entries() {
        let data = "\
[Proxy]
ss1 = ss, 1.1.1.1, 1111, encrypt-method=aes-256-gcm, password=p1
ss2 = ss, 2.2.2.2, 2222, encrypt-method=chacha20, password=p2";
        let proxies = parse_surfboard(data);
        assert_eq!(proxies.len(), 2);
    }

    #[test]
    fn test_parse_subscribe_singbox_dispatch() {
        let data = r#"[{"type":"ss","tag":"s1","server":"1.1.1.1","server_port":1111,"method":"aes","password":"p1"}]"#;
        let proxies = parse_subscribe(data);
        assert_eq!(proxies.len(), 1, "should detect and dispatch to sing-box parser");
    }

    #[test]
    fn test_parse_subscribe_surfboard_dispatch() {
        let data = "\
[Proxy]
test = ss, 1.2.3.4, 8388, encrypt-method=aes, password=p1";
        let proxies = parse_subscribe(data);
        assert_eq!(proxies.len(), 1, "should detect and dispatch to surfboard parser");
    }

    #[test]
    fn test_parse_subscribe_quantumult_dispatch() {
        let data = "shadowsocks=1.2.3.4:8388, method=chacha20, password=pass, tag=ss1";
        let proxies = parse_subscribe(data);
        assert_eq!(proxies.len(), 1, "should detect and dispatch to quantumult parser");
    }

    #[test]
    fn test_parse_subscribe_unknown_format() {
        let proxies = parse_subscribe("just some regular text");
        assert!(proxies.is_empty(), "unknown format should return empty");
    }
}
