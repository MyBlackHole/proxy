use rand::Rng;
use regex::Regex;
use std::collections::HashMap;

use crate::error::*;
use crate::mailtm;

const EMAIL_DOMAINS: &[&str] = &[
    "gmail.com", "outlook.com", "163.com", "126.com",
    "sina.com", "hotmail.com", "qq.com", "foxmail.com",
    "yahoo.com",
];

#[derive(Debug, Clone)]
pub struct RegisterRequire {
    pub need_email_verify: bool,
    pub need_invite_code: bool,
    pub need_captcha: bool,
    pub whitelist: Vec<String>,
    pub api_prefix: String,
}

async fn sniff_url(client: &reqwest::Client, url: &str) -> i32 {
    match client.get(url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
    {
        Ok(resp) => resp.status().as_u16() as i32,
        Err(_) => -2,
    }
}

pub async fn is_sspanel(client: &reqwest::Client, domain: &str) -> bool {
    let domain = domain.trim_end_matches('/');
    let paths = [
        format!("{}/api/v1/passport/auth/login", domain),
        format!("{}/api?scheme=passport/auth/login", domain),
    ];
    for path in &paths {
        if sniff_url(client, path).await == 200 {
            return false;
        }
    }
    sniff_url(client, &format!("{}/auth/login", domain)).await == 200
}

fn extract_domain(url: &str, include_protocol: bool) -> String {
    let re = Regex::new(r"^(https?://)?(?:www\.)?([^/]+)").unwrap();
    if let Some(caps) = re.captures(url) {
        if include_protocol && let Some(proto) = caps.get(1) && let Some(host) = caps.get(2) {
            return format!("{}{}", proto.as_str(), host.as_str());
        }
        caps.get(2).map_or(url.to_string(), |m| m.as_str().to_string())
    } else {
        url.to_string()
    }
}

pub async fn get_register_require(client: &reqwest::Client, domain: &str) -> Result<RegisterRequire> {
    let domain = extract_domain(domain, true);
    let api_prefixes = ["/api/v1/", "/api?scheme="];
    let mut result = RegisterRequire {
        need_email_verify: true,
        need_invite_code: true,
        need_captcha: true,
        whitelist: Vec::new(),
        api_prefix: String::new(),
    };

    for prefix in &api_prefixes {
        let url = format!("{}{}guest/comm/config", domain, prefix);
        match client.get(&url).send().await {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                if text.starts_with('{') && text.ends_with('}')
                    && let Ok(data) = serde_json::from_str::<serde_json::Value>(&text)
                    && let Some(config) = data.get("data")
                {
                    let verify = config.get("is_email_verify").and_then(|v| v.as_u64()).unwrap_or(0) != 0;
                    let invite = config.get("is_invite_force").and_then(|v| v.as_u64()).unwrap_or(0) != 0;
                    let captcha = config.get("is_recaptcha").and_then(|v| v.as_u64()).unwrap_or(0) != 0;
                    let whitelist = config.get("email_whitelist_suffix")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    result = RegisterRequire {
                        need_email_verify: verify,
                        need_invite_code: invite,
                        need_captcha: captcha,
                        whitelist,
                        api_prefix: prefix.to_string(),
                    };
                    return Ok(result);
                }
            }
            Err(_) => continue,
        }
    }
    Ok(result)
}

fn random_string(length: usize, punctuation: bool) -> String {
    use rand::seq::SliceRandom;
    let chars: Vec<char> = if punctuation {
        let mut c: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*".chars().collect();
        let mut rng = rand::thread_rng();
        c.shuffle(&mut rng);
        c
    } else {
        "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect()
    };
    let mut rng = rand::thread_rng();
    (0..length).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

fn build_headers(domain: &str, cookies: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string());
    h.insert("Referer".to_string(), format!("{}/", domain));
    h.insert("Origin".to_string(), domain.to_string());
    if !cookies.is_empty() {
        h.insert("Cookie".to_string(), cookies.to_string());
    }
    h
}

async fn post_form(client: &reqwest::Client, url: &str, params: &HashMap<&str, String>, headers: &HashMap<String, String>, jsonify: bool) -> Result<String> {
    let mut req = client.post(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if jsonify {
        req = req.header("Content-Type", "application/json");
        let mut map = serde_json::Map::new();
        for (k, v) in params {
            map.insert(k.to_string(), serde_json::Value::String(v.clone()));
        }
        req = req.json(&map);
    } else {
        req = req.header("Content-Type", "application/x-www-form-urlencoded");
        let vec_params: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        req = req.form(&vec_params);
    }
    let resp = req.send().await?;
    Ok(resp.text().await.unwrap_or_default())
}

async fn send_email_verify(client: &reqwest::Client, url: &str, email: &str, api_prefix: &str, headers: &HashMap<String, String>) -> Result<bool> {
    let jsonify = api_prefix == "/api?scheme=";
    let mut params = HashMap::new();
    params.insert("email", email.to_string());

    for attempt in 0..3 {
        match post_form(client, url, &params, headers, jsonify).await {
            Ok(text) => {
                let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
                return Ok(data.get("data").and_then(|v| v.as_bool()).unwrap_or(false));
            }
            Err(_) if attempt < 2 => {}
            Err(_) => return Ok(false),
        }
    }
    Ok(false)
}

async fn register_inner(
    client: &reqwest::Client,
    domain: &str,
    email: &str,
    passwd: &str,
    invite_code: &str,
    api_prefix: &str,
    jsonify: bool,
) -> Result<String> {
    let url = format!("{}{}passport/auth/register", domain.trim_end_matches('/'), api_prefix);
    let password = if passwd.is_empty() {
        random_string(rand::thread_rng().gen_range(8..17), true)
    } else {
        passwd.to_string()
    };
    let mut params = HashMap::new();
    params.insert("email", email.to_string());
    params.insert("password", password);
    params.insert("invite_code", invite_code.to_string());
    params.insert("email_code", String::new());

    let headers = build_headers(domain, "");

    for attempt in 0..3 {
        match post_form(client, &url, &params, &headers, jsonify).await {
            Ok(text) => {
                let data: serde_json::Value = serde_json::from_str(&text).map_err(|e| AppError::InvalidConfig(format!("register parse: {}", e)))?;
                let resp_data = data.get("data");
                let token = resp_data.and_then(|d| d.get("token")).and_then(|v| v.as_str()).unwrap_or("");

                let sub_url = format!("{}/api/v1/client/subscribe?token={}", domain.trim_end_matches('/'), token);
                return Ok(sub_url);
            }
            Err(_) if attempt < 2 => {}
            Err(e) => return Err(e),
        }
    }
    Err(AppError::Storage("register failed after retries".to_string()))
}

pub async fn register(
    client: &reqwest::Client,
    domain: &str,
    email: &str,
    passwd: &str,
    invite_code: &str,
) -> Result<String> {
    register_inner(client, domain, email, passwd, invite_code, "", false).await
}

pub async fn auto_register(
    client: &reqwest::Client,
    domain: &str,
    _email: &str,
    passwd: &str,
    invite_code: &str,
) -> Result<String> {
    let domain = domain.trim_end_matches('/');
    let mut rr = get_register_require(client, domain).await?;
    rr.api_prefix = if rr.api_prefix.is_empty() { "/api/v1/".to_string() } else { rr.api_prefix };
    let jsonify = rr.api_prefix == "/api?scheme=";

    if !rr.need_email_verify {
        let email_domain = if !rr.whitelist.is_empty() {
            let mut rng = rand::thread_rng();
            rr.whitelist[rng.gen_range(0..rr.whitelist.len())].clone()
        } else {
            let mut rng = rand::thread_rng();
            EMAIL_DOMAINS[rng.gen_range(0..EMAIL_DOMAINS.len())].to_string()
        };
        let local = random_string(rand::thread_rng().gen_range(6..11), false);
        let final_email = format!("{}@{}", local, email_domain);
        let pw = if passwd.is_empty() { random_string(rand::thread_rng().gen_range(8..17), true) } else { passwd.to_string() };
        return register_inner(client, domain, &final_email, &pw, invite_code, &rr.api_prefix, jsonify).await;
    }

    let mailbox = mailtm::create_temp_mail("mailtm")
        .map_err(|_| AppError::Storage("cannot create temp mail".to_string()))?;
    let account = mailbox.get_account().await
        .map_err(|_| AppError::Storage("cannot get temp account".to_string()))?;

    let send_url = format!("{}{}passport/comm/sendEmailVerify", domain, rr.api_prefix);
    let headers = build_headers(domain, "");
    let sent = send_email_verify(client, &send_url, &account.email, &rr.api_prefix, &headers).await?;
    if !sent {
        let _ = mailbox.delete_account(&account).await;
        return Err(AppError::Storage("failed to send email verify".to_string()));
    }

    let code = mailbox.monitor_verification_code(&account, 120).await
        .map_err(|_| AppError::Storage("no verification code received".to_string()))?;
    let _ = mailbox.delete_account(&account).await;

    let url = format!("{}{}passport/auth/register", domain, rr.api_prefix);
    let pw = if passwd.is_empty() { random_string(rand::thread_rng().gen_range(8..17), true) } else { passwd.to_string() };
    let mut params = HashMap::new();
    params.insert("email", account.email.clone());
    params.insert("password", pw);
    params.insert("invite_code", invite_code.to_string());
    params.insert("email_code", code);

    let text = post_form(client, &url, &params, &headers, jsonify).await?;
    let data: serde_json::Value = serde_json::from_str(&text).map_err(|e| AppError::InvalidConfig(format!("register parse: {}", e)))?;
    let token = data.get("data").and_then(|d| d.get("token")).and_then(|v| v.as_str()).unwrap_or("");
    Ok(format!("{}/api/v1/client/subscribe?token={}", domain, token))
}

pub async fn fetch_subscribe(_client: &reqwest::Client, url: &str, proxy: Option<&str>) -> Result<String> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120));
    if let Some(proxy_url) = proxy {
        let p = reqwest::Proxy::all(proxy_url)
            .map_err(|e| AppError::InvalidProxy(e.to_string()))?;
        builder = builder.proxy(p);
    }
    let cli = builder.build().map_err(|e| AppError::InvalidConfig(e.to_string()))?;
    let resp = cli.get(url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36; Clash.Meta; Mihomo; Shadowrocket")
        .send()
        .await?;
    let text = resp.text().await?;
    if text.starts_with('{') && text.ends_with('}')
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&text)
            && val.get("outbounds").is_none() {
                return Err(AppError::InvalidConfig("invalid subscription response".to_string()));
            }
    Ok(text)
}
