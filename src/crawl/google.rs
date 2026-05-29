use regex::Regex;
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
    let mut results = Vec::new();

    let url_re = Regex::new(
        r#"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/?(?:<em(?:\s+)?class="qkunPe">/?)?api/v1/client/subscribe\?token(?:</em>)?=[a-zA-Z0-9]{16,32}"#,
    );
    let url_re = match url_re {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[crawl_google] failed to compile URL regex: {}", e);
            return Ok(results);
        }
    };

    for start in (0..limit).step_by(num_per_page) {
        let url = format!(
            "https://www.google.com/search?q={}&hl=zh-CN&num={}&start={}",
            encoded, num_per_page, start
        );

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
                    break;
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
                    if !results.contains(&s) {
                        results.push(s);
                    }
                }

                // Also find broader subscription/proxy patterns in cleaned text
                results.extend(extract_subscribes(&cleaned));
            }
    }

    results.sort();
    results.dedup();

    Ok(results)
}
