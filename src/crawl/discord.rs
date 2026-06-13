use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Semaphore;

use super::extract_subscribes;
use super::build_crawl_client;
use crate::config::DiscordCrawlConfig;
use crate::config::SettingsConfig;
use crate::proxy::ProxyNode;

pub async fn crawl_discord(
    config: &DiscordCrawlConfig,
    settings: &SettingsConfig,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
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

    let channel_config = config.channels.clone();
    let bot_token = config.bot_token.clone();
    let limit = config.limit;

    let sem = Arc::new(Semaphore::new(5));
    let mut channel_handles = Vec::with_capacity(channel_config.len());

    for channel_id in channel_config {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let bot_token = bot_token.clone();

        let inline_tx = inline_tx.clone();
        channel_handles.push(tokio::spawn(async move {
            let _guard = permit;
            let url = format!(
                "https://discord.com/api/v10/channels/{}/messages?limit={}",
                channel_id, limit
            );
            log::debug!("[discord] GET channel: {}", url);

            let resp = match client
                .get(&url)
                .header("Authorization", format!("Bot {}", bot_token))
                .header("User-Agent", "DiscordBot (proxy-collector, 0.1.0)")
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    log::warn!("[discord] channel {} returned HTTP {}", channel_id, r.status());
                    return Vec::new();
                }
                Err(e) => {
                    log::warn!("[discord] failed to fetch channel {}: {}", channel_id, e);
                    return Vec::new();
                }
            };

            let messages: Vec<serde_json::Value> = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("[discord] failed to parse messages for channel {}: {}", channel_id, e);
                    return Vec::new();
                }
            };

            let mut channel_results = Vec::new();

            for msg in &messages {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    let mut inline = Vec::new();
                    channel_results.extend(extract_subscribes(content, &mut inline));
                    for p in inline { let _ = inline_tx.send(p); }
                }

                if let Some(embeds) = msg.get("embeds").and_then(|v| v.as_array()) {
                    for embed in embeds {
                        if let Some(desc) = embed.get("description").and_then(|v| v.as_str()) {
                            let mut inline = Vec::new();
                            channel_results.extend(extract_subscribes(desc, &mut inline));
                            for p in inline { let _ = inline_tx.send(p); }
                        }
                        if let Some(title) = embed.get("title").and_then(|v| v.as_str()) {
                            let mut inline = Vec::new();
                            channel_results.extend(extract_subscribes(title, &mut inline));
                            for p in inline { let _ = inline_tx.send(p); }
                        }
                        if let Some(fields) = embed.get("fields").and_then(|v| v.as_array()) {
                            for field in fields {
                                if let Some(value) = field.get("value").and_then(|v| v.as_str()) {
                                    let mut inline = Vec::new();
                                    channel_results.extend(extract_subscribes(value, &mut inline));
                                    for p in inline { let _ = inline_tx.send(p); }
                                }
                            }
                        }
                    }
                }

                // Fetch attachment content sequentially (attachments are rare, 0-3 per message)
                if let Some(attachments) = msg.get("attachments").and_then(|v| v.as_array())
                    && !attachments.is_empty()
                {
                    for attachment in attachments {
                        if let Some(url_str) = attachment.get("url").and_then(|v| v.as_str())
                            && (url_str.ends_with(".txt") || url_str.ends_with(".yaml")
                                || url_str.ends_with(".yml") || url_str.ends_with(".conf"))
                        {
                            log::debug!("[discord] GET attachment: {}", url_str);
                            if let Ok(resp) = client.get(url_str).send().await
                                && let Ok(text) = resp.text().await
                            {
                                let mut inline = Vec::new();
                                channel_results.extend(extract_subscribes(&text, &mut inline));
                                for p in inline { let _ = inline_tx.send(p); }
                            }
                        }
                    }
                }
            }

            channel_results
        }));
    }

    let mut results = Vec::new();
    for handle in channel_handles {
        if let Ok(urls) = handle.await {
            results.extend(urls);
        }
    }

    results.sort();
    results.dedup();
    results
}
