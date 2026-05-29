use std::sync::Arc;

use rand::Rng;
use regex::Regex;
use tokio::sync::Semaphore;
use std::time::Duration;

use crate::error::*;

pub struct TempAccount {
    pub email: String,
    pub password: String,
    pub auth_token: Option<String>,
    pub id: Option<String>,
}

pub struct TempMessage {
    pub from: String,
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
}

struct MailTMState {
    api_address: String,
}

struct RootShState {
    api_address: String,
}

struct SnapMailState {
    api_address: String,
}

struct LinShiState {
    api_address: String,
}

enum TempMailInner {
    MailTM(MailTMState),
    RootSh(RootShState),
    SnapMail(SnapMailState),
    LinShi(LinShiState),
}

pub struct TempMail {
    inner: TempMailInner,
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

fn extract_code(text: &str) -> Option<String> {
    let patterns = [
        r"您的验证码是：([0-9]{6})",
        r"验证码.*?(\d{4,8})",
        r"[：\s]+([0-9]{6})",
        r"\d{4,8}",
    ];
    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(caps) = re.captures(text) {
                if caps.len() > 1 {
                    let m = caps.get(1).map_or("", |m| m.as_str());
                    if !m.is_empty() {
                        return Some(m.to_string());
                    }
                }
                let m = caps.get(0).map_or("", |m| m.as_str());
                if m.len() >= 4 && m.len() <= 8 && m.chars().all(|c| c.is_ascii_digit()) {
                    return Some(m.to_string());
                }
            }
    }
    None
}

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default()
}

impl TempMail {
    pub async fn get_domain(&self) -> Result<String> {
        match &self.inner {
            TempMailInner::MailTM(state) => {
                let client = build_client();
                let resp = client.get(format!("{}/domains?page=1", state.api_address))
                    .header("Accept", "application/ld+json")
                    .send()
                    .await?;
                let data: serde_json::Value = resp.json().await?;
                let members = data.get("hydra:member").and_then(|v| v.as_array()).ok_or_else(|| {
                    AppError::InvalidConfig("no domains found".to_string())
                })?;
                let domain = members.first().and_then(|m| m.get("domain"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidConfig("no domain field".to_string()))?;
                Ok(domain.to_string())
            }
            TempMailInner::RootSh(state) => {
                let client = build_client();
                let resp = client.get(&state.api_address)
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .send()
                    .await?;
                let content = resp.text().await?;
                let re = Regex::new(r#"<li><a\s+href="javascript:;">([a-zA-Z0-9\.\-]+)</a></li>"#).unwrap();
                let domains: Vec<&str> = re.captures_iter(&content).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
                if domains.is_empty() {
                    return Err(AppError::InvalidConfig("no domains from rootsh".to_string()));
                }
                let mut rng = rand::thread_rng();
                Ok(domains[rng.gen_range(0..domains.len())].to_string())
            }
            TempMailInner::SnapMail(_) => {
                let domains = ["snapmail.cc", "lista.cc", "xxxhi.cc"];
                let mut rng = rand::thread_rng();
                Ok(domains[rng.gen_range(0..domains.len())].to_string())
            }
            TempMailInner::LinShi(state) => {
                let client = build_client();
                let resp = client.get(&state.api_address).send().await?;
                let content = resp.text().await?;
                let re = Regex::new(r#"data-mailhost="@([a-zA-Z0-9\-_\.]+)""#).unwrap();
                let domains: Vec<String> = re.captures_iter(&content).filter_map(|c| {
                    c.get(1).map(|m| m.as_str().to_string())
                }).filter(|d| d != "idrrate.com").collect();
                if domains.is_empty() {
                    return Err(AppError::InvalidConfig("no domains from linshi".to_string()));
                }
                let mut rng = rand::thread_rng();
                Ok(domains[rng.gen_range(0..domains.len())].clone())
            }
        }
    }

    pub async fn get_account(&self) -> Result<TempAccount> {
        match &self.inner {
            TempMailInner::MailTM(_) => {
                let client = build_client();
                let domain = self.get_domain().await?;
                let mut rng = rand::thread_rng();
                let username: String = random_string(rng.gen_range(6..13), false);
                let password: String = random_string(rng.gen_range(8..17), true);
                let email = format!("{}@{}", username, domain);

                let account_body = serde_json::json!({"address": email, "password": password});
                let resp = client.post("https://api.mail.tm/accounts")
                    .header("Accept", "application/ld+json")
                    .header("Content-Type", "application/json")
                    .json(&account_body)
                    .send()
                    .await?;
                let account_data: serde_json::Value = resp.json().await?;
                let account_id = account_data.get("id").and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidConfig("no account id".to_string()))?;
                let account_email = account_data.get("address").and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidConfig("no address".to_string()))?;

                let token_body = serde_json::json!({"address": email, "password": password});
                let token_resp = client.post("https://api.mail.tm/token")
                    .header("Accept", "application/ld+json")
                    .header("Content-Type", "application/json")
                    .json(&token_body)
                    .send()
                    .await?;
                let token_data: serde_json::Value = token_resp.json().await?;
                let token = token_data.get("token").and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::InvalidConfig("no token".to_string()))?;

                Ok(TempAccount {
                    email: account_email.to_string(),
                    password,
                    auth_token: Some(token.to_string()),
                    id: Some(account_id.to_string()),
                })
            }
            TempMailInner::RootSh(state) => {
                let client = build_client();
                let domain = self.get_domain().await?;
                let mut rng = rand::thread_rng();
                let username: String = random_string(rng.gen_range(6..13), false);
                let email = format!("{}@{}", username, domain);

                let resp = client.post(format!("{}/applymail", state.api_address))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .form(&[("mail", email.as_str())])
                    .send()
                    .await?;
                let text = resp.text().await?;
                let data: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| AppError::InvalidConfig("rootsh applymail parse error".to_string()))?;
                let success = data.get("success").and_then(|v| v.as_str()).unwrap_or("false");
                if success != "true" {
                    return Err(AppError::InvalidConfig("rootsh applymail failed".to_string()));
                }
                Ok(TempAccount {
                    email,
                    password: String::new(),
                    auth_token: None,
                    id: None,
                })
            }
            TempMailInner::SnapMail(_) => {
                let domain = self.get_domain().await?;
                let mut rng = rand::thread_rng();
                let username: String = random_string(rng.gen_range(6..13), false);
                let email = format!("{}@{}", username, domain);
                Ok(TempAccount {
                    email,
                    password: String::new(),
                    auth_token: None,
                    id: None,
                })
            }
            TempMailInner::LinShi(_) => {
                let domain = self.get_domain().await?;
                let mut rng = rand::thread_rng();
                let username: String = random_string(rng.gen_range(6..13), false);
                let email = format!("{}@{}", username, domain);
                Ok(TempAccount {
                    email,
                    password: String::new(),
                    auth_token: None,
                    id: None,
                })
            }
        }
    }

    pub async fn get_messages(&self, account: &TempAccount) -> Result<Vec<TempMessage>> {
        match &self.inner {
            TempMailInner::MailTM(_) => {
                let client = build_client();
                let token = account.auth_token.as_ref()
                    .ok_or_else(|| AppError::InvalidConfig("no auth token for MailTM".to_string()))?;
                let resp = client.get("https://api.mail.tm/messages?page=1")
                    .header("Accept", "application/ld+json")
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await?;
                let data: serde_json::Value = resp.json().await?;
                let members = data.get("hydra:member").and_then(|v| v.as_array())
                    .ok_or_else(|| AppError::InvalidConfig("no messages".to_string()))?;
                let sem = Arc::new(Semaphore::new(10));
                let mut msg_handles = Vec::with_capacity(members.len());
                for item in members {
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let client = client.clone();
                    let token = token.clone();
                    let msg_id = item.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();
                    if msg_id.is_empty() { continue; }
                    msg_handles.push(tokio::spawn(async move {
                        let _guard = permit;
                        let detail_url = format!("https://api.mail.tm/messages/{}", msg_id);
                        log::debug!("[mailtm] GET message detail: {}", detail_url);
                        if let Ok(resp) = client.get(&detail_url)
                            .header("Accept", "application/ld+json")
                            .header("Authorization", format!("Bearer {}", token))
                            .send()
                            .await
                            && let Ok(detail) = resp.json::<serde_json::Value>().await
                        {
                            let from = detail.get("from").and_then(|v| v.get("address"))
                                .and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let subject = detail.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let text = detail.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let html = detail.get("html").and_then(|v| v.as_str()).map(|s| s.to_string());
                            Some(TempMessage { from, subject, body: text, html_body: html })
                        } else {
                            None
                        }
                    }));
                }
                let mut messages = Vec::new();
                for handle in msg_handles {
                    if let Some(msg) = handle.await.unwrap_or(None) {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
            TempMailInner::RootSh(state) => {
                let client = build_client();
                let resp = client.post(format!("{}/getmail", state.api_address))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .form(&[("mail", account.email.as_str()), ("time", "0")])
                    .send()
                    .await?;
                let text = resp.text().await?;
                let data: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| AppError::InvalidConfig("rootsh getmail parse error".to_string()))?;
                let success = data.get("success").and_then(|v| v.as_str()).unwrap_or("false");
                if success != "true" {
                    return Ok(Vec::new());
                }
                let mails = data.get("mail").and_then(|v| v.as_array())
                    .ok_or_else(|| AppError::InvalidConfig("no mail array".to_string()))?;
                let sem = Arc::new(Semaphore::new(10));
                let mut mail_handles = Vec::with_capacity(mails.len());
                for mail in mails {
                    let arr = match mail.as_array() {
                        Some(a) if a.len() >= 5 => a,
                        _ => continue,
                    };
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let client = client.clone();
                    let api_address = state.api_address.clone();
                    let address_encoded = account.email.replace("@", "(a)").replace(".", "-_-");
                    let sender = arr[1].as_str().unwrap_or("").to_string();
                    let subject = arr[2].as_str().unwrap_or("").to_string();
                    let mail_id = arr[4].as_str().unwrap_or("").to_string();

                    mail_handles.push(tokio::spawn(async move {
                        let _guard = permit;
                        let content_url = format!("{}/win/{}/{}", api_address, address_encoded, mail_id);
                        log::debug!("[rootsh] GET mail content: {}", content_url);
                        if let Ok(r) = client.get(&content_url).send().await {
                            let body = r.text().await.unwrap_or_else(|e| {
                                log::warn!("Failed to read rootsh message body {}: {}", content_url, e);
                                String::new()
                            });
                            Some(TempMessage {
                                from: sender,
                                subject,
                                body,
                                html_body: None,
                            })
                        } else {
                            None
                        }
                    }));
                }
                let mut messages = Vec::new();
                for handle in mail_handles {
                    if let Some(msg) = handle.await.unwrap_or(None) {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
            TempMailInner::SnapMail(state) => {
                let client = build_client();
                let url = format!("{}/emaillist/{}", state.api_address, account.email);
                let resp = client.get(&url).send().await?;
                let text = resp.text().await?;
                let emails: Vec<serde_json::Value> = serde_json::from_str(&text)
                    .unwrap_or_default();
                let mut messages = Vec::new();
                for email in emails {
                    let html = email.get("html").and_then(|v| v.as_str()).unwrap_or("");
                    if html.is_empty() { continue; }
                    let from = email.get("from").and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("").to_string();
                    let subject = email.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    messages.push(TempMessage {
                        from,
                        subject,
                        body: html.to_string(),
                        html_body: Some(html.to_string()),
                    });
                }
                Ok(messages)
            }
            TempMailInner::LinShi(state) => {
                let client = build_client();
                let username = account.email.split('@').next().unwrap_or("");
                let url = format!("{}/api/v1/mailbox/{}", state.api_address, username);
                let resp = client.get(&url).send().await?;
                let text = resp.text().await?;
                let emails: Vec<serde_json::Value> = serde_json::from_str(&text)
                    .unwrap_or_default();
                let sem = Arc::new(Semaphore::new(10));
                let mut mail_handles = Vec::with_capacity(emails.len());
                for email in &emails {
                    let mail_id = email.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();
                    if mail_id.is_empty() { continue; }
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let client = client.clone();
                    let api_address = state.api_address.clone();
                    let username = username.to_string();
                    let from = email.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let subject = email.get("subject").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    mail_handles.push(tokio::spawn(async move {
                        let _guard = permit;
                        let content_url = format!("{}/mailbox/{}/{}", api_address, username, mail_id);
                        log::debug!("[linshi] GET mail content: {}", content_url);
                        if let Ok(r) = client.get(&content_url).send().await {
                            let body = r.text().await.unwrap_or_else(|e| {
                                log::warn!("Failed to read linshi message body {}: {}", content_url, e);
                                String::new()
                            });
                            Some(TempMessage {
                                from,
                                subject,
                                body,
                                html_body: None,
                            })
                        } else {
                            None
                        }
                    }));
                }
                let mut messages = Vec::new();
                for handle in mail_handles {
                    if let Some(msg) = handle.await.unwrap_or(None) {
                        messages.push(msg);
                    }
                }
                Ok(messages)
            }
        }
    }

    pub async fn monitor_verification_code(&self, account: &TempAccount, timeout_secs: u64) -> Result<String> {
        let start = std::time::Instant::now();
        let timeout = timeout_secs.min(600);
        let sleep_secs = 3u64;
        let initial = self.get_messages(account).await.unwrap_or_else(|e| {
            log::warn!("Failed to get initial messages for {}: {}", account.email, e);
            Vec::new()
        });
        let mut last_count = initial.len();

        while start.elapsed().as_secs() < timeout {
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            let messages = self.get_messages(account).await.unwrap_or_else(|e| {
                log::warn!("Failed to poll messages for {}: {}", account.email, e);
                Vec::new()
            });
            if messages.len() > last_count {
                for msg in &messages {
                    if let Some(code) = extract_code(&msg.body) {
                        return Ok(code);
                    }
                    if let Some(ref html) = msg.html_body
                        && let Some(code) = extract_code(html) {
                            return Ok(code);
                        }
                }
                last_count = messages.len();
            }
        }
        Err(AppError::Storage("verification code not found within timeout".to_string()))
    }

    pub async fn delete_account(&self, account: &TempAccount) -> Result<()> {
        match &self.inner {
            TempMailInner::MailTM(_) => {
                let client = build_client();
                let token = account.auth_token.as_ref()
                    .ok_or_else(|| AppError::InvalidConfig("no auth token".to_string()))?;
                let account_id = account.id.as_ref()
                    .ok_or_else(|| AppError::InvalidConfig("no account id".to_string()))?;
                client.delete(format!("https://api.mail.tm/accounts/{}", account_id))
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await?;
                Ok(())
            }
            TempMailInner::RootSh(state) => {
                let client = build_client();
                client.post(format!("{}/destroymail", state.api_address))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .form(&[("_", "0")])
                    .send()
                    .await?;
                Ok(())
            }
            TempMailInner::SnapMail(_) => {
                Err(AppError::Storage("delete not supported for SnapMail".to_string()))
            }
            TempMailInner::LinShi(_) => {
                log::info!("linshiyouxiang delete account noop");
                Ok(())
            }
        }
    }
}

pub fn create_temp_mail(provider: &str) -> Result<TempMail> {
    match provider.to_lowercase().as_str() {
        "mailtm" => Ok(TempMail {
            inner: TempMailInner::MailTM(MailTMState {
                api_address: "https://api.mail.tm".to_string(),
            }),
        }),
        "rootsh" => Ok(TempMail {
            inner: TempMailInner::RootSh(RootShState {
                api_address: "https://rootsh.com".to_string(),
            }),
        }),
        "snapmail" => Ok(TempMail {
            inner: TempMailInner::SnapMail(SnapMailState {
                api_address: "https://snapmail.cc".to_string(),
            }),
        }),
        "linshi" | "linshiyouxiang" => Ok(TempMail {
            inner: TempMailInner::LinShi(LinShiState {
                api_address: "https://linshiyouxiang.net".to_string(),
            }),
        }),
        _ => Err(AppError::InvalidConfig(format!("unknown temp mail provider: {}", provider))),
    }
}
