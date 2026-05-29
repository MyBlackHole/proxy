use regex::Regex;
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
    let mut results = Vec::new();

    let re = Regex::new(
        r"https?://(?:[a-zA-Z0-9_\-]+\.)+[a-zA-Z0-9_\-]+(?::\d+)?/<b>api</b>/<b>v</b><b>1</b>/<b>client</b>/<b>subscribe</b>\?<b>token</b>=[a-zA-Z0-9]{16,32}",
    );
    let re = match re {
        Ok(r) => r,
        Err(_) => return Ok(results),
    };

    for page in 0..total_pages {
        let url = format!("{}&p={}", base_url, page);

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
                    if !results.contains(&s) {
                        results.push(s);
                    }
                }

                // Also find broader subscription/proxy patterns in cleaned text
                let cleaned = text.replace("<b>", "").replace("</b>", "").replace("<br>", "");
                results.extend(extract_subscribes(&cleaned));
            }
    }

    results.sort();
    results.dedup();

    Ok(results)
}
