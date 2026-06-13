use std::sync::Arc;
use regex::Regex;

use super::depth::crawl_items_with_extractor;
use super::extract_subscribes;
use super::extractor::ContentExtractor;
use crate::config::PageCrawlConfig;

pub(crate) fn extract_page_links(content: &str) -> Vec<String> {
    let link_re = match Regex::new(r#"https?://[^\s"'<>]+"#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    let mut links = Vec::new();
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
        links.push(link);
    }
    links
}

/// Page link extractor: feeds HTML page links into the shared depth engine.
///
/// - `extract_terminal`: subscription/proxy URLs found on the page
/// - `extract_sub_sources`: filtered page links for further crawling
pub struct PageLinkExtractor;

impl ContentExtractor for PageLinkExtractor {
    fn extract_terminal(&self, content: &str) -> Vec<String> {
        extract_subscribes(content)
    }

    fn extract_sub_sources(&self, content: &str) -> Vec<String> {
        extract_page_links(content)
    }
}

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
                        // Depth crawling via shared engine
                        if page_config.depth > 0 {
                            let page_links = extract_page_links(&text);
                            if !page_links.is_empty() {
                                results.extend(
                                    crawl_items_with_extractor(
                                        client,
                                        &page_links,
                                        page_config.depth - 1,
                                        concurrency,
                                        Arc::new(PageLinkExtractor),
                                    )
                                    .await,
                                );
                            }
                        }
                    }
            }
        } else if let Ok(resp) = client.get(url).send().await
        && let Ok(text) = resp.text().await {
            log::debug!("[crawl_pages] GET (sequential): {}", url);
            results.extend(extract_subscribes(&text));
            // Depth crawling via shared engine
            if page_config.depth > 0 {
                let page_links = extract_page_links(&text);
                if !page_links.is_empty() {
                    results.extend(
                        crawl_items_with_extractor(
                            client,
                            &page_links,
                            page_config.depth - 1,
                            concurrency,
                            Arc::new(PageLinkExtractor),
                        )
                        .await,
                    );
                }
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
                    let page_links = extract_page_links(&text);
                    if !page_links.is_empty() {
                        let extractor = Arc::new(PageLinkExtractor);
                        page_results.extend(
                            crawl_items_with_extractor(
                                &client,
                                &page_links,
                                depth - 1,
                                concurrency,
                                extractor,
                            )
                            .await,
                        );
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_page_links_basic() {
        let html = r#"
            <a href="https://example.com/page1">Page 1</a>
            <a href="https://example.com/page2">Page 2</a>
        "#;
        let links = extract_page_links(html);
        assert_eq!(links.len(), 2);
        assert!(links.contains(&"https://example.com/page1".to_string()));
        assert!(links.contains(&"https://example.com/page2".to_string()));
    }

    #[test]
    fn test_extract_page_links_excludes_subscribe() {
        let html = r#"
            <a href="https://example.com/page1">Good</a>
            <a href="https://example.com/subscribe">Subscribe</a>
            <a href="https://example.com/link?token=abc123">Token</a>
            <a href="vmess://abc123">VMess</a>
        "#;
        let links = extract_page_links(html);
        assert_eq!(links.len(), 1);
        assert!(links.contains(&"https://example.com/page1".to_string()));
    }

    #[test]
    fn test_extract_page_links_dedup() {
        let html = r#"
            <a href="https://example.com/page1">Page 1</a>
            <a href="https://example.com/page1">Page 1 again</a>
        "#;
        let links = extract_page_links(html);
        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_extract_page_links_limit() {
        let mut html = String::new();
        for i in 0..30 {
            html.push_str(&format!("<a href=\"https://example.com/page{}\">Page {}</a>\n", i, i));
        }
        let links = extract_page_links(&html);
        assert!(links.len() <= 20, "should limit to 20 links, got {}", links.len());
    }

    #[test]
    fn test_extract_page_links_no_links() {
        let html = "just some text without URLs";
        let links = extract_page_links(html);
        assert!(links.is_empty());
    }

    #[test]
    fn test_page_link_extractor_terminal() {
        let extractor = PageLinkExtractor;
        let content = "some text vmess://eyJhZGQiOiIxLjIuMy40In0= trojan://pass@host:443 more";
        let results = extractor.extract_terminal(content);
        assert!(!results.is_empty(), "should extract proxy links from page content");
        assert!(results.iter().any(|r| r.starts_with("vmess://")));
    }

    #[test]
    fn test_page_link_extractor_sub_sources() {
        let extractor = PageLinkExtractor;
        let html = r#"
            <a href="https://example.com/page1">Page 1</a>
            <a href="https://example.com/subscribe">Subscribe</a>
        "#;
        let results = extractor.extract_sub_sources(html);
        assert_eq!(results.len(), 1, "should extract page links, excluding subscribe");
        assert_eq!(results[0], "https://example.com/page1");
    }
}
