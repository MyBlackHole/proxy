use std::sync::Arc;

use regex::Regex;
use tokio::sync::Semaphore;

use crate::error::*;

use super::extract_subscribes;

pub async fn crawl_yandex(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
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

        handles.push(tokio::spawn(async move {
            let _guard = permit;
            let url = format!("{}&p={}", base_url, page);
            log::debug!("[crawl_yandex] GET search page {}: {}", page, url);

            let mut page_results = Vec::new();
            if let Ok(resp) = client
                .get(&url)
                .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .send()
                .await
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
                    page_results.extend(extract_subscribes(&cleaned));
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
