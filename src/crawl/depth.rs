use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Semaphore;

use super::extractor::ContentExtractor;
use crate::subscribe;

// ── Classification ──────────────────────────────────────────────────────

pub enum Item {
    Terminal(String),
    Resolvable(Source),
}

pub fn classify(item: &str) -> Item {
    let s = item.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        Item::Resolvable(Source::Http(s.to_string()))
    } else if s.contains("://") {
        Item::Terminal(s.to_string())
    } else if is_base64_candidate(s) {
        Item::Resolvable(Source::Base64(s.to_string()))
    } else {
        Item::Terminal(s.to_string())
    }
}

// ── Source Resolution ──────────────────────────────────────────────────

pub enum Source {
    Http(String),
    Base64(String),
}

impl Source {
    pub async fn resolve(&self, client: &reqwest::Client) -> Option<String> {
        match self {
            Source::Http(url) => match subscribe::fetch_with_client(client, url).await {
                Ok(body) => Some(body),
                Err(e) => {
                    log::debug!("[depth] fetch failed: {}: {}", url, e);
                    None
                }
            },
            Source::Base64(encoded) => {
                let stripped: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(decoded) = subscribe::decode_base64_subscription(&stripped) {
                    return Some(decoded);
                }
                let mut lines = Vec::new();
                for line in encoded.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.len() < 10 {
                        continue;
                    }
                    if let Ok(decoded) = subscribe::decode_base64_subscription(trimmed) {
                        lines.push(decoded);
                    }
                }
                if lines.is_empty() { None } else { Some(lines.join("\n")) }
            }
        }
    }
}

// ── Public Entry Points ────────────────────────────────────────────────

/// Depth-crawl items using the default `SubscriptionExtractor`.
///
/// Signature preserved for backward compatibility.
pub fn crawl_items_with_depth<'a>(
    client: &'a reqwest::Client,
    items: &'a [String],
    depth: usize,
    concurrency: usize,
) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
    crawl_items_with_extractor(
        client,
        items,
        depth,
        concurrency,
        Arc::new(super::extractor::SubscriptionExtractor),
    )
}

/// Depth-crawl items using a custom `ContentExtractor`.
///
/// Shared engine used by `SubscriptionExtractor` (depth.rs) and
/// `PageLinkExtractor` (pages.rs).
pub fn crawl_items_with_extractor<'a>(
    client: &'a reqwest::Client,
    items: &'a [String],
    depth: usize,
    concurrency: usize,
    extractor: Arc<dyn ContentExtractor>,
) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
    process_items(client, items, depth, concurrency, true, extractor)
}

// ── Core Recursive Processor ───────────────────────────────────────────

fn process_items<'a>(
    client: &'a reqwest::Client,
    items: &'a [String],
    remaining: usize,
    concurrency: usize,
    spawn: bool,
    extractor: Arc<dyn ContentExtractor>,
) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
    Box::pin(async move {
        // remaining == 0: process items (classify + resolve + extract_terminal) but do NOT recurse.
        // The recursion guard is in process_raw_content (remaining > 1).
        if items.is_empty() {
            return Vec::new();
        }

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut results: Vec<String> = Vec::new();
        let mut tasks: Vec<tokio::task::JoinHandle<Vec<String>>> = Vec::new();

        for item in items {
            match classify(item) {
                Item::Terminal(link) => results.push(link),

                Item::Resolvable(source) => {
                    if spawn {
                        let c = client.clone();
                        let sem = semaphore.clone();
                        let ext = Arc::clone(&extractor);
                        tasks.push(tokio::spawn(async move {
                            let _p = sem.acquire_owned().await.unwrap();
                            match source.resolve(&c).await {
                                Some(content) => {
                                    process_raw_content(&c, &content, remaining, concurrency, &ext).await
                                }
                                None => Vec::new(),
                            }
                        }));
                    } else {
                        let _p = semaphore.acquire().await.unwrap();
                        if let Some(content) = source.resolve(client).await {
                            results.extend(
                                process_raw_content(client, &content, remaining, concurrency, &extractor).await,
                            );
                        }
                    }
                }
            }
        }

        for task in tasks {
            if let Ok(links) = task.await {
                results.extend(links);
            }
        }

        results
    })
}

// ── Shared Content Processing ──────────────────────────────────────────

async fn process_raw_content(
    client: &reqwest::Client,
    content: &str,
    remaining: usize,
    concurrency: usize,
    extractor: &Arc<dyn ContentExtractor>,
) -> Vec<String> {
    let mut results = extractor.extract_terminal(content);

    if remaining > 1 {
        let sub_items = extractor.extract_sub_sources(content);
        if !sub_items.is_empty() {
            let deeper = process_items(
                client,
                &sub_items,
                remaining - 1,
                concurrency,
                false,
                Arc::clone(extractor),
            )
            .await;
            results.extend(deeper);
        }
    }

    results
}

// ── Helpers ────────────────────────────────────────────────────────────

fn is_base64_candidate(s: &str) -> bool {
    if s.len() < 20 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_http_url() {
        match classify("http://example.com/sub") {
            Item::Resolvable(Source::Http(url)) => assert_eq!(url, "http://example.com/sub"),
            _ => panic!("expected Resolvable(Http)"),
        }
    }

    #[test]
    fn test_classify_https_url() {
        match classify("https://example.com/sub") {
            Item::Resolvable(Source::Http(url)) => assert_eq!(url, "https://example.com/sub"),
            _ => panic!("expected Resolvable(Http)"),
        }
    }

    #[test]
    fn test_classify_proxy_link() {
        match classify("vmess://abc123") {
            Item::Terminal(link) => assert_eq!(link, "vmess://abc123"),
            _ => panic!("expected Terminal"),
        }
    }

    #[test]
    fn test_classify_base64() {
        match classify("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=") {
            Item::Resolvable(Source::Base64(s)) => assert_eq!(s, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="),
            _ => panic!("expected Resolvable(Base64)"),
        }
    }

    #[test]
    fn test_classify_plain_text() {
        match classify("plain text") {
            Item::Terminal(s) => assert_eq!(s, "plain text"),
            _ => panic!("expected Terminal"),
        }
    }

    #[test]
    fn test_classify_trojan_url() {
        match classify("trojan://password@example.com:443") {
            Item::Terminal(link) => assert_eq!(link, "trojan://password@example.com:443"),
            _ => panic!("expected Terminal for trojan URL"),
        }
    }

    #[test]
    fn test_is_base64_candidate_valid() {
        assert!(is_base64_candidate("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));
    }

    #[test]
    fn test_is_base64_candidate_too_short() {
        assert!(!is_base64_candidate("short"));
    }

    #[test]
    fn test_is_base64_candidate_invalid_chars() {
        assert!(!is_base64_candidate("YWJjZGVmZ2hpamtsbW5vcHFy!!c3R1dnd4eXoxMjM0NTY="));
    }

    #[test]
    fn test_is_base64_candidate_with_whitespace() {
        // base64 with whitespace is still a candidate (whitespace is stripped during resolve)
        assert!(is_base64_candidate("YWJjZGVm Z2hpamts bW5vcHFy c3R1dnd4 eXoxMjM0 NTY="));
    }
}
