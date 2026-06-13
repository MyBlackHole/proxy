use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use regex::Regex;
use tokio::sync::Semaphore;

use tokio::sync::mpsc;
use crate::error::*;
use crate::proxy::ProxyNode;

use super::extract_subscribes;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

pub async fn crawl_yandex(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let base_url = format!(
        r#"https://yandex.com/search/?text="{}"&lr=10599&cee=1&within=2"#,
        encoded
    );
    let total_pages = pages.clamp(1, 20);

    let re = Regex::new(
        r"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/<b>api</b>/<b>v</b><b>1</b>/<b>client</b>/<b>subscribe</b>\?<b>token</b>=[a-zA-Z0-9]{16,32}",
    );
    let re = match re {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[crawl_yandex] failed to compile URL regex: {}", e);
            return Ok(Vec::new());
        }
    };

    let sem = Arc::new(Semaphore::new(5));
    let mut handles = Vec::with_capacity(total_pages);

    for page in 0..total_pages {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let base_url = base_url.clone();
        let re = re.clone();

        // Pre-generate random values outside async block (ThreadRng is !Send)
        let delays: [u64; 3] = [
            rand::thread_rng().gen_range(100..300),
            rand::thread_rng().gen_range(100..300),
            rand::thread_rng().gen_range(100..300),
        ];
        let uas: [&str; 3] = [
            USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())],
            USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())],
            USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())],
        ];

        let inline_tx = inline_tx.clone();
        handles.push(tokio::spawn(async move {
            let _guard = permit;
            let url = format!("{}&p={}", base_url, page);
            log::debug!("[crawl_yandex] GET search page {}: {}", page, url);

            let mut page_results = Vec::new();

            let mut resp_opt = None;
            for attempt in 1..=3 {
                if attempt > 1 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                tokio::time::sleep(Duration::from_millis(delays[attempt - 1])).await;

                if let Ok(resp) = client
                    .get(&url)
                    .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
                    .header("User-Agent", uas[attempt - 1])
                    .send()
                    .await
                {
                    resp_opt = Some(resp);
                    break;
                }
                log::warn!(
                    "[crawl_yandex] attempt {}/3 failed for page={}",
                    attempt,
                    page
                );
            }

            if let Some(resp) = resp_opt
                && let Ok(text) = resp.text().await {
                    for m in re.find_iter(&text) {
                        let s = m
                            .as_str()
                            .replace("<b>", "")
                            .replace("</b>", "");
                        let s = if let Some(rest) = s.strip_prefix("http://") {
                            format!("https://{}", rest)
                        } else {
                            s
                        };
                        if !page_results.contains(&s) {
                            page_results.push(s);
                        }
                    }

                    let cleaned = text.replace("<b>", "").replace("</b>", "").replace("<br>", "");
                    let mut inline = Vec::new();
                    page_results.extend(extract_subscribes(&cleaned, &mut inline));
                    for p in inline { let _ = inline_tx.send(p); }
                }
            page_results
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(urls) = handle.await {
            results.extend(urls);
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}
