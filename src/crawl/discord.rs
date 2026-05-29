use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::DiscordCrawlConfig;
use crate::config::SettingsConfig;

pub async fn crawl_discord(
    config: &DiscordCrawlConfig,
    settings: &SettingsConfig,
) -> Vec<String> {
    if config.bot_token.is_empty() {
        return Vec::new();
    }

    let client = match build_crawl_client(settings.socks_proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("[discord] failed to build HTTP client: {}", e);
            return Vec::new();
        }
    };

    let mut results: Vec<String> = Vec::new();

    for channel_id in &config.channels {
        let url = format!(
            "https://discord.com/api/v10/channels/{}/messages?limit={}",
            channel_id, config.limit
        );

        let resp = match client
            .get(&url)
            .header("Authorization", format!("Bot {}", config.bot_token))
            .header("User-Agent", "DiscordBot (proxy-collector, 0.1.0)")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[discord] channel {} returned HTTP {}", channel_id, r.status());
                continue;
            }
            Err(e) => {
                log::warn!("[discord] failed to fetch channel {}: {}", channel_id, e);
                continue;
            }
        };

        let messages: Vec<serde_json::Value> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[discord] failed to parse messages for channel {}: {}", channel_id, e);
                continue;
            }
        };

        for msg in &messages {
            if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                results.extend(extract_subscribes(content));
            }

            if let Some(embeds) = msg.get("embeds").and_then(|v| v.as_array()) {
                for embed in embeds {
                    if let Some(desc) = embed.get("description").and_then(|v| v.as_str()) {
                        results.extend(extract_subscribes(desc));
                    }
                    if let Some(title) = embed.get("title").and_then(|v| v.as_str()) {
                        results.extend(extract_subscribes(title));
                    }
                    if let Some(fields) = embed.get("fields").and_then(|v| v.as_array()) {
                        for field in fields {
                            if let Some(value) = field.get("value").and_then(|v| v.as_str()) {
                                results.extend(extract_subscribes(value));
                            }
                        }
                    }
                }
            }

            if let Some(attachments) = msg.get("attachments").and_then(|v| v.as_array()) {
                for attachment in attachments {
                    if let Some(url_str) = attachment.get("url").and_then(|v| v.as_str()) {
                        if url_str.ends_with(".txt") || url_str.ends_with(".yaml")
                            || url_str.ends_with(".yml") || url_str.ends_with(".conf")
                        {
                            if let Ok(resp) = client.get(url_str).send().await
                                && let Ok(text) = resp.text().await
                            {
                                results.extend(extract_subscribes(&text));
                            }
                        }
                    }
                }
            }
        }
    }

    results.sort();
    results.dedup();
    results
}
