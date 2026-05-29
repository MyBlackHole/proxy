use regex::Regex;
use crate::error::*;

use super::extract_subscribes;

pub async fn crawl_telegram(client: &reqwest::Client, channel: &str, pages: usize) -> Result<Vec<String>> {
    if pages > 1 {
        let page_count = get_telegram_page_count(client, channel).await.unwrap_or(0);
        if page_count == 0 {
            return Ok(Vec::new());
        }

        let mut values: Vec<i64> = (0..=page_count).rev().step_by(100).collect();
        values.truncate(pages);

        let mut results = Vec::new();
        for before in values {
            let url = format!("https://t.me/s/{}?before={}", channel, before);
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await {
                    results.extend(extract_subscribes(&text));
                }
        }

        results.sort();
        results.dedup();
        return Ok(results);
    }

    let url = format!("https://t.me/s/{}", channel);
    let resp = client.get(&url).send().await?;
    let text = resp.text().await?;
    Ok(extract_subscribes(&text))
}

async fn get_telegram_page_count(client: &reqwest::Client, channel: &str) -> Result<i64> {
    let url = format!("https://t.me/s/{}", channel);
    let resp = client.get(&url).send().await?;
    let text = resp.text().await?;

    let pattern = format!(
        r#"<link\s+rel="canonical"\s+href="/s/{}\?before=(\d+)">"#,
        regex::escape(channel)
    );
    let re = Regex::new(&pattern).map_err(|e| AppError::InvalidConfig(e.to_string()))?;

    if let Some(caps) = re.captures(&text)
        && let Some(before) = caps.get(1)
            && let Ok(n) = before.as_str().parse::<i64>() {
                return Ok(n);
            }

    Ok(0)
}

/// Extended version that also fetches historical messages.
pub async fn crawl_telegram_history(
    client: &reqwest::Client,
    channel: &str,
    pages: usize,
    history_depth: usize,
) -> Result<Vec<String>> {
    let mut results = crawl_telegram(client, channel, pages).await?;

    if history_depth > 0 {
        let extra_pages = history_depth.min(50);
        if let Ok(page_count) = get_telegram_page_count(client, channel).await
            && page_count > 0 {
                let values: Vec<i64> = (0..=page_count)
                    .rev()
                    .step_by(100)
                    .skip(pages + 1)
                    .take(extra_pages)
                    .collect();

                for before in values {
                    let url = format!("https://t.me/s/{}?before={}", channel, before);
                    if let Ok(resp) = client.get(&url).send().await
                        && let Ok(text) = resp.text().await
                    {
                        results.extend(extract_subscribes(&text));
                    }
                }
            }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Search public Telegram groups by keyword via t.me search
pub async fn crawl_telegram_search(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();

    for page in 0..pages {
        if page == 0 {
            let url = format!("https://t.me/search?q={}", urlencoding(query));
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await {
                    results.extend(extract_subscribes(&text));
                }
        }

        let search_url = format!("https://t.me/search?q={}&page={}", urlencoding(query), page);
        if let Ok(resp) = client.get(&search_url).send().await
            && let Ok(text) = resp.text().await {
                results.extend(extract_subscribes(&text));
            }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

fn urlencoding(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}
