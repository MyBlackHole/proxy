use tokio::sync::mpsc;
use crate::error::*;
use crate::proxy::ProxyNode;
use super::extract_subscribes;

/// Crawl Reddit subreddits for proxy links using Reddit's public JSON API.
///
/// The Reddit JSON API is accessible without authentication for public subreddits.
/// Rate limit: 60 requests per minute (we stay well below this).
pub async fn crawl_reddit(
    client: &reqwest::Client,
    subreddits: &[String],
    limit: usize,
    inline_tx: mpsc::UnboundedSender<ProxyNode>,
) -> Result<Vec<String>> {
    let mut all_results = Vec::new();
    let max_limit = limit.min(100); // Reddit API max per request

    for subreddit in subreddits {
        log::info!("[crawl_reddit] Fetching r/{}", subreddit);

        // Fetch latest posts from subreddit
        let url = format!(
            "https://www.reddit.com/r/{}/hot.json?limit={}",
            subreddit, max_limit
        );

        if let Ok(resp) = client
            .get(&url)
            .header("User-Agent", "Mozilla/5.0 (compatible; ProxyCollector/1.0)")
            .send()
            .await
            && let Ok(text) = resp.text().await
        {
            // Try to parse JSON response and extract post titles + content
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(children) = json["data"]["children"].as_array() {
                    for child in children {
                        if let Some(post) = child["data"].as_object() {
                            // Collect title + selftext + url for extraction
                            let mut text_content = String::new();
                            if let Some(title) = post.get("title").and_then(|v| v.as_str()) {
                                text_content.push_str(title);
                                text_content.push('\n');
                            }
                            if let Some(selftext) = post.get("selftext").and_then(|v| v.as_str()) {
                                text_content.push_str(selftext);
                                text_content.push('\n');
                            }
                            if let Some(url) = post.get("url").and_then(|v| v.as_str()) {
                                text_content.push_str(url);
                                text_content.push('\n');
                            }

                            if !text_content.is_empty() {
                                let mut inline = Vec::new();
                                all_results.extend(extract_subscribes(&text_content, &mut inline));
                                for p in inline { let _ = inline_tx.send(p); }
                            }
                        }
                    }
                }
        }

        // Brief delay between subreddits to respect rate limits
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    all_results.sort();
    all_results.dedup();
    log::info!("[crawl_reddit] Found {} unique URLs from {} subreddits", all_results.len(), subreddits.len());
    Ok(all_results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_proxy_links_from_reddit_text() {
        // Proxy links found in Reddit text are extracted by the pipeline's
        // extractor stage from fetched content, not by extract_subscribes.
        let text = "Check out this free proxy: ss://YWVzLTI1Ni1nY206dGVzdEAxMjcuMC4wLjE6ODM4OA==\nAlso try trojan://password@example.com:443";
        let results = extract_subscribes(text, &mut vec![]);
        assert!(results.is_empty(), "proxy links are not subscribe URLs");
    }
}
