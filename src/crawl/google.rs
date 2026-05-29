use std::sync::Arc;

use regex::Regex;
use tokio::sync::Semaphore;

use crate::error::*;

use super::extract_subscribes;

pub async fn crawl_google(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let num_per_page = 100;
    let limit = (pages * num_per_page).min(1000);

    let url_re = Regex::new(
        r#"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/?(?:<em(?:\s+)?class="qkunPe">/?)?api/v1/client/subscribe\?token(?:</em>)?=[a-zA-Z0-9]{16,32}"#,
    );
    let url_re = match url_re {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[crawl_google] failed to compile URL regex: {}", e);
            return Ok(Vec::new());
        }
    };

    let pages_vec: Vec<usize> = (0..limit).step_by(num_per_page).collect();
    let sem = Arc::new(Semaphore::new(3));
    let mut handles = Vec::with_capacity(pages_vec.len());

    for start in pages_vec {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let encoded = encoded.clone();
        let url_re = url_re.clone();

        handles.push(tokio::spawn(async move {
            let _guard = permit;
            let url = format!(
                "https://www.google.com/search?q={}&hl=zh-CN&num={}&start={}",
                encoded, num_per_page, start
            );
            log::debug!("[crawl_google] GET search page start={}: {}", start, url);

            let mut page_results = Vec::new();
            if let Ok(resp) = client
                .get(&url)
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .send()
                .await
                && let Ok(text) = resp.text().await {
                    let cleaned = text
                        .replace("\\n", "")
                        .replace("\\u003d", "=");

                    if cleaned.contains("did not match any documents")
                        || cleaned.contains("找不到和您查询的")
                    {
                        return page_results;
                    }

                    for m in url_re.find_iter(&cleaned) {
                        let s = m
                            .as_str()
                            .replace("<em class=\"qkunPe\">", "")
                            .replace("</em>", "")
                            .replace("<em>", "")
                            .replace(' ', "");
                        let s = if let Some(rest) = s.strip_prefix("http://") {
                            format!("https://{}", rest)
                        } else {
                            s
                        };
                        if !page_results.contains(&s) {
                            page_results.push(s);
                        }
                    }

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
