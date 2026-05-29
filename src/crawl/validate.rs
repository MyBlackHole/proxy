use crate::error::*;

#[derive(Debug, Clone)]
pub enum SubscribeStatus {
    Valid {
        upload: u64,
        download: u64,
        total: u64,
        expire: Option<u64>,
    },
    Invalid(String),
    Expired,
}

pub fn is_valid_subscribe(status: &SubscribeStatus) -> bool {
    matches!(status, SubscribeStatus::Valid { .. })
}

pub fn is_expired(status: &SubscribeStatus) -> bool {
    matches!(status, SubscribeStatus::Expired)
}

pub async fn validate_subscribe(client: &reqwest::Client, url: &str) -> Result<SubscribeStatus> {
    let resp = client.get(url).send().await?;
    let status = resp.status();

    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(SubscribeStatus::Expired);
    }

    if !status.is_success() {
        return Ok(SubscribeStatus::Invalid(format!("HTTP {}", status.as_u16())));
    }

    let userinfo_header = resp.headers().get("subscription-userinfo").cloned();
    let content = resp.text().await?;
    if content.len() < 32 {
        return Ok(SubscribeStatus::Expired);
    }

    if let Some(userinfo) = userinfo_header
        && let Ok(header_str) = userinfo.to_str() {
            let mut upload = 0u64;
            let mut download = 0u64;
            let mut total = 0u64;
            let mut expire: Option<u64> = None;

            for part in header_str.split(';') {
                let kv: Vec<&str> = part.splitn(2, '=').collect();
                if kv.len() != 2 {
                    continue;
                }
                let key = kv[0].trim();
                let value = kv[1].trim();
                match key {
                    "upload" => upload = value.parse().unwrap_or(0),
                    "download" => download = value.parse().unwrap_or(0),
                    "total" => total = value.parse().unwrap_or(0),
                    "expire" => expire = value.parse().ok(),
                    _ => {}
                }
            }

            return Ok(SubscribeStatus::Valid {
                upload,
                download,
                total,
                expire,
            });
        }

    if content.contains("proxies:") || content.contains("://") {
        return Ok(SubscribeStatus::Valid {
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
    }

    Ok(SubscribeStatus::Invalid(
        "could not determine validity".into(),
    ))
}
