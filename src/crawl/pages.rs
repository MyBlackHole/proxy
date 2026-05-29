use std::sync::Arc;
use regex::Regex;
use tokio::sync::Semaphore;

use super::extract_subscribes;
use crate::config::PageCrawlConfig;

pub async fn crawl_pages(
    client: &reqwest::Client,
    urls: Vec<String>,
    page_config: &PageCrawlConfig,
) -> crate::error::Result<Vec<String>> {
    let concurrency = page_config.concurrency;
    if concurrency > 1 {
        return crawl_pages_concurrent(client, &urls, page_config, concurrency).await;
    }

    let mut results = Vec::new();

    for url in &urls {
        if page_config.multiple && !page_config.placeholder.is_empty() {
            for i in page_config.start..=page_config.end {
                let expanded = url.replace(&page_config.placeholder, &i.to_string());
                log::debug!("[crawl_pages] GET (sequential): {}", expanded);
                if let Ok(resp) = client.get(&expanded).send().await
                    && let Ok(text) = resp.text().await {
                        results.extend(extract_subscribes(&text));
                        // Depth crawling: follow links on the page
                        if page_config.depth > 0 {
                            results.extend(crawl_page_depth(client, &text, page_config.depth - 1).await);
                        }
                    }
            }
        } else if let Ok(resp) = client.get(url).send().await
        && let Ok(text) = resp.text().await {
            log::debug!("[crawl_pages] GET (sequential): {}", url);
            results.extend(extract_subscribes(&text));
            // Depth crawling: follow links on the page
            if page_config.depth > 0 {
                results.extend(crawl_page_depth(client, &text, page_config.depth - 1).await);
            }
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

async fn crawl_pages_concurrent(
    client: &reqwest::Client,
    urls: &[String],
    page_config: &PageCrawlConfig,
    concurrency: usize,
) -> crate::error::Result<Vec<String>> {
    let mut expanded_urls: Vec<String> = Vec::new();
    for url in urls {
        if page_config.multiple && !page_config.placeholder.is_empty() {
            for i in page_config.start..=page_config.end {
                let expanded = url.replace(&page_config.placeholder, &i.to_string());
                expanded_urls.push(expanded);
            }
        } else {
            expanded_urls.push(url.clone());
        }
    }

    if expanded_urls.is_empty() {
        return Ok(Vec::new());
    }

    let depth = page_config.depth;
    let client = client.clone();
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for url in expanded_urls {
        let client = client.clone();
        let permit = sem.clone().acquire_owned().await;

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            log::debug!("[crawl_pages] GET (concurrent): {}", url);
            let mut page_results = Vec::new();
            if let Ok(resp) = client.get(&url).send().await
                && let Ok(text) = resp.text().await
            {
                page_results.extend(extract_subscribes(&text));
                if depth > 0 {
                    page_results.extend(crawl_page_depth(&client, &text, depth - 1).await);
                }
            }
            page_results
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(page_results) = handle.await {
            results.extend(page_results);
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Recursively follow http/https links found in page content up to remaining depth.
/// Fetches links at each depth level concurrently using a bounded Semaphore.
fn crawl_page_depth<'a>(client: &'a reqwest::Client, content: &'a str, remaining: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>> {
    let content = content.to_string();
    let client = client.clone();
    Box::pin(async move {
        if remaining == 0 {
            return Vec::new();
        }

        let link_re = match Regex::new(r#"https?://[^\s"'<>]+"#) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[crawl_page_depth] failed to compile link regex: {}", e);
                return Vec::new();
            }
        };

        // Collect all links first (owned, with dedup and cap at 20)
        let mut seen = std::collections::HashSet::new();
        let mut links = Vec::new();
        for m in link_re.find_iter(&content) {
            let link = m.as_str().trim().to_string();
            if !link.starts_with("http://") && !link.starts_with("https://") {
                continue;
            }
            if link.contains("subscribe") || link.contains("token=") || link.contains("vmess://") {
                continue;
            }
            if !seen.insert(link.clone()) {
                continue;
            }
            if seen.len() > 20 {
                break;
            }
            links.push(link);
        }

        if links.is_empty() {
            return Vec::new();
        }

        let sem = Arc::new(Semaphore::new(10));
        let mut handles = Vec::with_capacity(links.len());

        for link in links {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                let _guard = permit;
                let mut page_results = Vec::new();
                log::debug!("[crawl_page_depth] GET: {}", link);
                if let Ok(resp) = client.get(&link).send().await
                    && let Ok(text) = resp.text().await
                {
                    page_results.extend(extract_subscribes(&text));
                    if remaining > 1 {
                        // Recurse using the same pattern (sequential at deeper levels)
                        // to avoid unbounded spawning
                        page_results.extend(
                            crawl_page_depth_inner(&client, &text, remaining - 1).await
                        );
                    }
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
        results
    })
}

fn crawl_page_depth_inner<'a>(client: &'a reqwest::Client, content: &'a str, remaining: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + 'a>> {
    Box::pin(async move {
        if remaining == 0 {
            return Vec::new();
        }

        let link_re = match Regex::new(r#"https?://[^\s"'<>]+"#) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[crawl_page_depth] failed to compile link regex: {}", e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for m in link_re.find_iter(content) {
            let link = m.as_str().trim().to_string();
            if !link.starts_with("http://") && !link.starts_with("https://") {
                continue;
            }
            if link.contains("subscribe") || link.contains("token=") || link.contains("vmess://") {
                continue;
            }
            if !seen.insert(link.clone()) {
                continue;
            }
            if seen.len() > 20 {
                break;
            }

            log::debug!("[crawl_page_depth] GET: {}", link);
            if let Ok(resp) = client.get(&link).send().await
                && let Ok(text) = resp.text().await
            {
                results.extend(extract_subscribes(&text));
                if remaining > 1 {
                    results.extend(crawl_page_depth_inner(client, &text, remaining - 1).await);
                }
            }
        }

        results
    })
}
