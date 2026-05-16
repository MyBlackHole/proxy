use crate::error::{AppError, Result};
use crate::proxy::*;
use base64::Engine as _;
use std::collections::HashMap;
use url::Url;

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
    } else {
        Err(AppError::InvalidProxy(format!(
            "unsupported protocol: {}",
            input.split("://").next().unwrap_or(input)
        )))
    }
}

fn parse_query_params(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn parse_host_port(host: &str, port_str: &str, default_port: u16) -> Result<(String, u16)> {
    if !port_str.is_empty() {
        let port: u16 = port_str
            .parse()
            .map_err(|_| AppError::InvalidProxy(format!("invalid port: {}", port_str)))?;
        Ok((host.to_string(), port))
    } else if let Some(idx) = host.rfind(':') {
        let h = &host[..idx];
        let p: u16 = host[idx + 1..]
            .parse()
            .map_err(|_| AppError::InvalidProxy(format!("invalid port in host: {}", host)))?;
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
    String::from_utf8(bytes).map_err(|_| AppError::InvalidProxy("base64 decode not utf-8".into()))
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
    String::from_utf8(bytes).map_err(|_| AppError::InvalidProxy("base64 decode not utf-8".into()))
}

fn extract_name_from_url(url: &Url) -> Option<String> {
    url.fragment()
        .map(|s| {
            percent_encoding::percent_decode(s.as_bytes())
                .decode_utf8()
                .map(|c| c.to_string())
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
        .map_err(|_| AppError::InvalidProxy(format!("vmess: invalid port: {}", port_str)))?;

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

    let ws_path = vm
        .remove("path")
        .or_else(|| vm.remove("wspath"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let ws_headers = vm
        .remove("host")
        .or_else(|| vm.remove("headers"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .map(|h| {
            let mut map = HashMap::new();
            map.insert("Host".to_string(), h);
            map
        });

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
            let (creds, host_part) = decoded.split_once('@').unwrap();
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

    let password = url.username().to_string();
    if password.is_empty() {
        return Err(AppError::InvalidProxy("trojan: missing password".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "trojan"));
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

    Ok(ProxyNode::Trojan(TrojanConfig {
        name,
        server: host.to_string(),
        port,
        password,
        sni,
        alpn,
        skip_cert_verify,
        udp,
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
        .map_err(|_| AppError::InvalidProxy(format!("ssr: invalid port: {}", parts[1])))?;
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

    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return Err(AppError::InvalidProxy("vless: missing uuid".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "vless"));

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

    let username = url.username().to_string();
    let password = url.password().map(|s| s.to_string());

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "http"));
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

    let username = url.username().to_string();
    let password = url.password().map(|s| s.to_string());

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "socks5"));
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

    let password = url.username().to_string();
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

    let uuid = url.username().to_string();
    let token = url.password().unwrap_or("").to_string();
    if uuid.is_empty() || token.is_empty() {
        return Err(AppError::InvalidProxy("tuic: missing uuid or token".into()));
    }

    let params = parse_query_params(&url);
    let name = extract_name_from_url(&url).unwrap_or_else(|| default_name(host, port, "tuic"));

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

    let psk = url.username().to_string();
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

    let password = url.username().to_string();
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
}
