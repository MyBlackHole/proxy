use regex::Regex;
use tokio::sync::mpsc;
use crate::error::*;
use crate::proxy::ProxyNode;

use super::extract_subscribes;

static TWITTER_BEARER: &str =
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

async fn get_twitter_guest_token(client: &reqwest::Client) -> Result<String> {
    let resp = client
        .get("https://twitter.com/")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await?;

    let text = resp.text().await?;
    let re = Regex::new(r"gt=([0-9]{19})")
        .map_err(|e| AppError::InvalidConfig(e.to_string()))?;

    if let Some(cap) = re.captures(&text)
        && let Some(gt) = cap.get(1) {
            return Ok(gt.as_str().to_string());
        }

    Err(AppError::Storage("could not extract twitter guest token".into()))
}

pub async fn crawl_twitter(
    client: &reqwest::Client,
    username: &str,
    count: usize,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Result<Vec<String>> {
    let guest_token = get_twitter_guest_token(client).await?;
    let tweet_count = count.clamp(1, 100);

    let auth_header = format!("Bearer {}", TWITTER_BEARER);

    let user_variables = serde_json::json!({
        "screen_name": username,
        "withSafetyModeUserFields": true,
    });
    let features = serde_json::json!({
        "blue_business_profile_image_shape_enabled": true,
        "responsive_web_graphql_exclude_directive_enabled": true,
        "verified_phone_label_enabled": false,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
        "responsive_web_graphql_timeline_navigation_enabled": true,
    });

    let user_url = format!(
        "https://twitter.com/i/api/graphql/sLVLhk0bGj3MVFEKTdax1w/UserByScreenName?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&user_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&user_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let user_id = body["data"]["user"]["result"]["rest_id"]
        .as_str()
        .ok_or_else(|| AppError::Storage("could not find twitter user id".into()))?
        .to_string();

    let timeline_variables = serde_json::json!({
        "userId": user_id,
        "count": tweet_count,
        "includePromotedContent": false,
        "withClientEventToken": false,
        "withBirdwatchNotes": false,
        "withVoice": true,
        "withV2Timeline": true,
    });

    let timeline_url = format!(
        "https://twitter.com/i/api/graphql/P7qs2Sf7vu1LDKbzDW9FSA/UserMedia?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&timeline_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&timeline_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let text = body.to_string();
    let mut inline = Vec::new();
    let results = extract_subscribes(&text, &mut inline);
    for p in inline { let _ = inline_tx.send(p); }

    Ok(results)
}

/// Search Twitter by keyword using the GraphQL search endpoint
pub async fn crawl_twitter_search(
    client: &reqwest::Client,
    query: &str,
    count: usize,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let guest_token = get_twitter_guest_token(client).await?;
    let tweet_count = count.clamp(1, 100);
    let auth_header = format!("Bearer {}", TWITTER_BEARER);

    let features = serde_json::json!({
        "blue_business_profile_image_shape_enabled": true,
        "responsive_web_graphql_exclude_directive_enabled": true,
        "verified_phone_label_enabled": false,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": false,
        "responsive_web_graphql_timeline_navigation_enabled": true,
    });

    let search_variables = serde_json::json!({
        "rawQuery": query,
        "count": tweet_count,
        "product": "Top",
        "includePromotedContent": false,
    });

    let search_url = format!(
        "https://twitter.com/i/api/graphql/gkjsKepM6glHm36JjW4V3A/SearchTimeline?variables={}&features={}",
        percent_encoding::utf8_percent_encode(&search_variables.to_string(), percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&features.to_string(), percent_encoding::NON_ALPHANUMERIC),
    );

    let resp = client
        .get(&search_url)
        .header("Authorization", &auth_header)
        .header("X-Guest-Token", &guest_token)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let text = body.to_string();
    let mut inline = Vec::new();
    let results = extract_subscribes(&text, &mut inline);
    for p in inline { let _ = inline_tx.send(p); }

    Ok(results)
}
