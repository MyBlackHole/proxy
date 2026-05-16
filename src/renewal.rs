use rand::Rng;
use std::collections::HashMap;

use crate::config::*;
use crate::error::*;

const PACKAGES: &[&str] = &[
    "month_price",
    "quarter_price",
    "half_year_price",
    "year_price",
    "two_year_price",
    "three_year_price",
    "onetime_price",
];

pub struct SubscribeInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire_days: i64,
    pub reset_day: Option<u32>,
    pub can_renew: bool,
}

pub struct Plan {
    pub id: usize,
    pub name: String,
    pub price: f64,
    pub is_free: bool,
}

fn build_headers(domain: &str, cookies: &str, auth: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("user-agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string());
    h.insert("referer".to_string(), format!("{}/", domain));
    if !cookies.is_empty() {
        h.insert("cookie".to_string(), cookies.to_string());
    }
    if !auth.is_empty() {
        h.insert("authorization".to_string(), auth.to_string());
    }
    h
}

async fn post_form(client: &reqwest::Client, url: &str, params: &HashMap<&str, String>, headers: &HashMap<String, String>, jsonify: bool) -> Result<reqwest::Response> {
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
    Ok(req.send().await?)
}

pub async fn login(client: &reqwest::Client, domain: &str, email: &str, passwd: &str) -> Result<(String, String)> {
    let url = format!("{}/api/v1/passport/auth/login", domain);
    let mut params = HashMap::new();
    params.insert("email", email.to_string());
    params.insert("password", passwd.to_string());

    for attempt in 0..3 {
        let headers = build_headers(domain, "", "");
        match post_form(client, &url, &params, &headers, false).await {
            Ok(resp) => {
                let status = resp.status();
                let cookies = resp.headers().get("set-cookie")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("").to_string();
                let text = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    let auth_data: serde_json::Value = serde_json::from_str(&text)
                        .unwrap_or(serde_json::Value::Null);
                    let auth = auth_data.get("data").and_then(|d| d.get("auth_data"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("").to_string();
                    return Ok((cookies, auth));
                }
                if attempt >= 2 {
                    return Ok((cookies, String::new()));
                }
            }
            Err(_) if attempt < 2 => {}
            Err(e) => return Err(e),
        }
    }
    Ok((String::new(), String::new()))
}

pub async fn get_subscribe_info(client: &reqwest::Client, domain: &str, cookies: &str, auth: &str) -> Result<SubscribeInfo> {
    let url = format!("{}/api/v1/user/getSubscribe", domain);
    let headers = build_headers(domain, cookies, auth);
    let mut req = client.post(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await?;
    let text = resp.text().await?;
    let data: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| AppError::InvalidConfig(format!("subscribe info parse: {}", e)))?;
    let info = data.get("data").ok_or_else(|| AppError::InvalidConfig("no data in subscribe info".to_string()))?;

    let _plan_id = info.get("plan_id").and_then(|v| v.as_u64()).unwrap_or(1);
    let timestamp = info.get("expired_at").and_then(|v| v.as_u64()).unwrap_or(32503651199);
    let reset_day = info.get("reset_day").and_then(|v| v.as_i64());

    let d = info.get("d").and_then(|v| v.as_u64()).unwrap_or(0);
    let transfer_enable = info.get("transfer_enable").and_then(|v| v.as_u64()).unwrap_or(1);

    let plan = info.get("plan");
    let renew_enable = plan.and_then(|p| p.get("renew")).and_then(|v| v.as_u64()).unwrap_or(0) == 1;

    let now = chrono::Utc::now().timestamp() as u64;
    let expire_days = if timestamp > now {
        ((timestamp - now) / 86400) as i64
    } else {
        -1
    };

    let reset = reset_day.map(|d| if d < 0 { 365u32 } else { d as u32 });

    Ok(SubscribeInfo {
        upload: d,
        download: 0,
        total: transfer_enable,
        expire_days,
        reset_day: reset,
        can_renew: renew_enable,
    })
}

pub async fn get_free_plan(client: &reqwest::Client, domain: &str, cookies: &str) -> Result<Option<Plan>> {
    let url = format!("{}/api/v1/user/plan/fetch", domain);
    let headers = build_headers(domain, cookies, "");
    let mut req = client.get(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await?;
    let text = resp.text().await?;
    let data: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| AppError::InvalidConfig(format!("plan fetch parse: {}", e)))?;
    let plans = data.get("data").and_then(|v| v.as_array())
        .ok_or_else(|| AppError::InvalidConfig("no plans data".to_string()))?;

    let discount = check_coupon(client, domain, "", &headers).await.ok().flatten();

    let mut candidates: Vec<(f64, usize, String)> = Vec::new();
    for plan_val in plans {
        let plan_id = plan_val.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let name = plan_val.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        for package in PACKAGES {
            let price = plan_val.get(package).and_then(|v| v.as_f64());
            let free = match price {
                None => false,
                Some(p) => is_free_price(p, &discount, plan_id, package),
            };
            if free {
                let traffic = plan_val.get("transfer_enable").and_then(|v| v.as_f64()).unwrap_or(0.0);
                candidates.push((traffic, plan_id, name.clone()));
                break;
            }
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(candidates.into_iter().next().map(|(_, id, name)| Plan {
        id,
        name,
        price: 0.0,
        is_free: true,
    }))
}

fn is_free_price(price: f64, discount: &Option<serde_json::Value>, plan_id: usize, package: &str) -> bool {
    if price <= 0.0 { return true; }
    let d = match discount { Some(v) => v, None => return false };
    let limit_plans = d.get("limit_plan_ids").and_then(|v| v.as_array());
    let limit_periods = d.get("limit_period").and_then(|v| v.as_array());
    if let Some(plans) = limit_plans {
        let pid_str = plan_id.to_string();
        if !plans.iter().any(|p| p.as_str() == Some(&pid_str)) {
            return false;
        }
    }
    if let Some(periods) = limit_periods
        && !periods.iter().any(|p| p.as_str() == Some(package)) {
            return false;
        }
    let dtype = d.get("type").and_then(|v| v.as_u64()).unwrap_or(1);
    let value = d.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
    match dtype {
        1 => (value - price).abs() < f64::EPSILON,
        _ => (value - 100.0).abs() < f64::EPSILON,
    }
}

async fn check_coupon(client: &reqwest::Client, domain: &str, coupon: &str, headers: &HashMap<String, String>) -> Result<Option<serde_json::Value>> {
    let url = format!("{}/api/v1/user/coupon/check", domain);
    let mut params = HashMap::new();
    params.insert("code", coupon.to_string());
    let resp = post_form(client, &url, &params, headers, false).await?;
    let text = resp.text().await?;
    let data: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| AppError::InvalidConfig(format!("coupon check parse: {}", e)))?;
    Ok(data.get("data").cloned())
}

async fn fetch_order_trade_no(client: &reqwest::Client, url: &str, headers: &HashMap<String, String>) -> Result<Option<String>> {
    for attempt in 0..3 {
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send().await {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
                if let Some(orders) = data.get("data").and_then(|v| v.as_array()) {
                    for order in orders {
                        if order.get("status").and_then(|v| v.as_u64()).unwrap_or(1) == 0 {
                            return Ok(order.get("trade_no").and_then(|v| v.as_str()).map(|s| s.to_string()));
                        }
                    }
                }
                return Ok(None);
            }
            Err(_) if attempt < 2 => {}
            Err(e) => return Err(AppError::Http(e)),
        }
    }
    Ok(None)
}

pub async fn order_plan(client: &reqwest::Client, domain: &str, plan_id: usize, cookies: &str, auth: &str, coupon: &str) -> Result<bool> {
    let url = format!("{}/api/v1/user/order/save", domain);
    let headers = build_headers(domain, cookies, auth);
    let mut params = HashMap::new();
    params.insert("plan_id", plan_id.to_string());
    params.insert("period", "month_price".to_string());
    if !coupon.is_empty() {
        params.insert("coupon_code", coupon.to_string());
    }
    let resp = post_form(client, &url, &params, &headers, false).await?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    let text = resp.text().await.unwrap_or_default();
    let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    Ok(data.get("data").is_some())
}

pub async fn checkout(client: &reqwest::Client, domain: &str, order_id: usize, cookies: &str, auth: &str, method: usize) -> Result<bool> {
    let fetch_url = format!("{}/api/v1/user/order/fetch", domain);
    let headers = build_headers(domain, cookies, auth);
    let trade_no = fetch_order_trade_no(client, &fetch_url, &headers).await?;
    let trade_no = match trade_no {
        Some(t) => t,
        None => {
            let order_url = format!("{}/api/v1/user/order/save", domain);
            let mut params = HashMap::new();
            params.insert("plan_id", order_id.to_string());
            params.insert("period", "month_price".to_string());
            let resp = post_form(client, &order_url, &params, &headers, false).await?;
            let text = resp.text().await.unwrap_or_default();
            let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            data.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string()
        }
    };
    if trade_no.is_empty() {
        return Err(AppError::InvalidConfig("no trade_no".to_string()));
    }
    let pay_url = format!("{}/api/v1/user/order/checkout", domain);
    let mut pay_params = HashMap::new();
    pay_params.insert("trade_no", trade_no);
    pay_params.insert("method", method.to_string());
    let resp = post_form(client, &pay_url, &pay_params, &headers, false).await?;
    let text = resp.text().await.unwrap_or_default();
    let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    Ok(data.get("data").and_then(|v| v.as_bool()).unwrap_or(false))
}

pub async fn register_free_plan(
    client: &reqwest::Client,
    domain: &str,
    email: &str,
    passwd: &str,
    plan_id: usize,
    coupon: &str,
    method: usize,
) -> Result<String> {
    let (cookies, auth) = login(client, domain, email, passwd).await?;

    let plan = get_free_plan(client, domain, &cookies).await?;
    let pid = plan.map(|p| p.id).unwrap_or(plan_id);

    let order_url = format!("{}/api/v1/user/order/save", domain);
    let headers = build_headers(domain, &cookies, &auth);
    let mut params = HashMap::new();
    params.insert("plan_id", pid.to_string());
    params.insert("period", "month_price".to_string());
    if !coupon.is_empty() {
        params.insert("coupon_code", coupon.to_string());
    }
    let resp = post_form(client, &order_url, &params, &headers, false).await?;
    let text = resp.text().await.unwrap_or_default();
    let order_data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    let trade_no = order_data.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if !trade_no.is_empty() {
        let pay_url = format!("{}/api/v1/user/order/checkout", domain);
        let mut pay_params = HashMap::new();
        pay_params.insert("trade_no", trade_no);
        pay_params.insert("method", method.to_string());
        let _ = post_form(client, &pay_url, &pay_params, &headers, false).await?;
    }

    let sub_url = format!("{}/api/v1/user/getSubscribe", domain);
    let mut sub_req = client.post(&sub_url);
    for (k, v) in &build_headers(domain, &cookies, &auth) {
        sub_req = sub_req.header(k.as_str(), v.as_str());
    }
    let sub_resp = sub_req.send().await?;
    let sub_text = sub_resp.text().await.unwrap_or_default();
    let sub_data: serde_json::Value = serde_json::from_str(&sub_text).unwrap_or(serde_json::Value::Null);
    let subscribe_url = sub_data.get("data").and_then(|d| d.get("subscribe_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .replace("\\", "");
    Ok(subscribe_url)
}

pub fn is_free_plan(plan: &Plan, coupon: &str) -> bool {
    if plan.is_free || plan.price <= 0.0 {
        return true;
    }
    !coupon.is_empty()
}

async fn get_payment_methods(client: &reqwest::Client, domain: &str, cookies: &str, auth: &str) -> Vec<usize> {
    let url = format!("{}/api/v1/user/order/getPaymentMethod", domain);
    let headers = build_headers(domain, cookies, auth);
    let mut req = client.get(&url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    match req.send().await {
        Ok(r) => {
            let text = r.text().await.unwrap_or_default();
            let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            data.get("data").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|item| item.get("id").and_then(|v| v.as_u64()).map(|id| id as usize)).collect())
                .unwrap_or_else(|| vec![1])
        }
        Err(_) => vec![1],
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn add_traffic_flow(
    client: &reqwest::Client,
    domain: &str,
    email: &str,
    passwd: &str,
    plan_id: usize,
    coupon: &str,
    method: usize,
    ticket_config: Option<&TicketConfig>,
) -> Result<String> {
    use base64::Engine;
    use base64::engine::general_purpose;

    let decoded_email = String::from_utf8(general_purpose::STANDARD.decode(email).map_err(|_| AppError::InvalidConfig("base64 decode email".to_string()))?)
        .map_err(|_| AppError::InvalidConfig("invalid email utf8".to_string()))?;
    let decoded_passwd = String::from_utf8(general_purpose::STANDARD.decode(passwd).map_err(|_| AppError::InvalidConfig("base64 decode passwd".to_string()))?)
        .map_err(|_| AppError::InvalidConfig("invalid passwd utf8".to_string()))?;

    let (cookies, auth) = login(client, domain, &decoded_email, &decoded_passwd).await?;

    let subscribe = get_subscribe_info(client, domain, &cookies, &auth).await?;

    let actual_plan_id = if plan_id > 0 { plan_id } else { 1 };

    let actual_method = if method > 0 {
        method
    } else {
        let methods = get_payment_methods(client, domain, &cookies, &auth).await;
        if methods.is_empty() {
            1
        } else {
            let mut rng = rand::thread_rng();
            methods[rng.gen_range(0..methods.len())]
        }
    };

    if subscribe.can_renew {
        let order_url = format!("{}/api/v1/user/order/save", domain);
        let headers = build_headers(domain, &cookies, &auth);
        let mut params = HashMap::new();
        params.insert("plan_id", actual_plan_id.to_string());
        params.insert("period", "month_price".to_string());
        if !coupon.is_empty() {
            params.insert("coupon_code", coupon.to_string());
        }
        let _ = post_form(client, &order_url, &params, &headers, false).await?;

        let fetch_url = format!("{}/api/v1/user/order/fetch", domain);
        if let Ok(Some(trade_no)) = fetch_order_trade_no(client, &fetch_url, &headers).await {
            let pay_url = format!("{}/api/v1/user/order/checkout", domain);
            let mut pay_params = HashMap::new();
            pay_params.insert("trade_no", trade_no);
            pay_params.insert("method", actual_method.to_string());
            let _ = post_form(client, &pay_url, &pay_params, &headers, false).await?;
        }
    }

    if let Some(ticket) = ticket_config
        && ticket.enable {
            let ticket_headers = build_headers(domain, &cookies, &auth);
            let subj = if ticket.subject.is_empty() { "traffic reset request".to_string() } else { ticket.subject.clone() };
            let msg = if ticket.message.is_empty() { "please reset my traffic".to_string() } else { ticket.message.clone() };
            let ticket_url = format!("{}/api/v1/user/ticket/save", domain);
            let mut ticket_params = HashMap::new();
            ticket_params.insert("subject", subj);
            ticket_params.insert("message", msg);
            ticket_params.insert("level", ticket.level.to_string());
            let _ = post_form(client, &ticket_url, &ticket_params, &ticket_headers, false).await?;
        }

    let sub_url = format!("{}/api/v1/user/getSubscribe", domain);
    let headers = build_headers(domain, &cookies, &auth);
    let mut sub_req = client.post(&sub_url);
    for (k, v) in &headers {
        sub_req = sub_req.header(k.as_str(), v.as_str());
    }
    let sub_resp = sub_req.send().await?;
    let sub_text = sub_resp.text().await.unwrap_or_default();
    let sub_data: serde_json::Value = serde_json::from_str(&sub_text).unwrap_or(serde_json::Value::Null);
    Ok(sub_data.get("data").and_then(|d| d.get("subscribe_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .replace("\\", ""))
}
