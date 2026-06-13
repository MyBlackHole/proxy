//! Multi-source proxy crawler module.
//!
//! Each source type has its own submodule:
//! - `telegram`: Telegram channel/page crawling
//! - `discord`: Discord channel message crawling
//! - `rss`: RSS/Atom feed crawling
//! - `proxy_site`: Known proxy aggregation sites
//! - `github`: GitHub code/issues/gists/topics/repo crawling
//! - `google`: Google search crawling
//! - `yandex`: Yandex search crawling
//! - `twitter`: Twitter user/search crawling
//! - `pages`: Custom web page crawling with depth
//! - `validate`: Subscribe URL validation
//! - `extract`: URL pattern extraction from text
//! - `client`: Shared HTTP client builder

mod client;
mod depth;
mod extract;
mod pipeline;
mod extractor;
mod validate;
mod telegram;
mod discord;
mod rss;
mod proxy_site;
mod github;
mod google;
mod yandex;
mod twitter;
mod pages;
mod reddit;
mod proxy_api;

pub use client::build_crawl_client;
pub use depth::{crawl_items_with_depth, crawl_items_with_extractor};
pub use pipeline::{run_pipeline, PipelineConfig};
pub use extract::extract_subscribes;
pub use extractor::{ContentExtractor, SubscriptionExtractor};
pub use validate::{SubscribeStatus, is_valid_subscribe, is_expired, validate_subscribe};
pub use telegram::*;
pub use discord::*;
pub use rss::*;
pub use proxy_site::*;
pub use github::*;
pub use google::*;
pub use yandex::*;
pub use twitter::*;
pub use pages::*;
pub use reddit::*;
pub use proxy_api::*;

use crate::config::PageCrawlConfig;
use crate::error::*;

/// Unified crawler source — each variant knows how to crawl itself
pub enum CrawlerSource {
    Telegram { name: String, pages: usize },
    GitHubSearch { query: String, pages: usize, token: String },
    GitHubUser { username: String, repo: String, depth: usize, token: String },
    Google { query: String, pages: usize },
    Yandex { query: String, pages: usize },
    Twitter { name: String, num: usize },
    CustomPage { url: String, config: PageCrawlConfig },
    GitHubRepo { username: String, repo_name: String, commits: usize, token: String },
}

impl CrawlerSource {
    pub async fn crawl(&self, client: &reqwest::Client) -> Result<Vec<String>> {
        match self {
            CrawlerSource::Telegram { name, pages } => crawl_telegram(client, name, *pages).await,
            CrawlerSource::GitHubSearch { query, pages, token } => crawl_github(client, query, *pages, token).await,
            CrawlerSource::GitHubUser { username, repo, depth, token } => crawl_github_repo(client, username, repo, *depth, token).await,
            CrawlerSource::Google { query, pages } => crawl_google(client, query, *pages).await,
            CrawlerSource::Yandex { query, pages } => crawl_yandex(client, query, *pages).await,
            CrawlerSource::Twitter { name, num } => crawl_twitter(client, name, *num).await,
            CrawlerSource::CustomPage { url, config } => {
                let urls = vec![url.clone()];
                crawl_pages(client, urls, config).await
            }
            CrawlerSource::GitHubRepo { username, repo_name, commits, token } => {
                crawl_github_repo(client, username, repo_name, *commits, token).await
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subscribes_direct_proxy_links() {
        let text = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ== trojan://password@1.2.3.4:443?peer=example.com";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 2, "should extract vmess and trojan links");
        assert!(results[0].starts_with("vmess://"));
        assert!(results[1].starts_with("trojan://"));
    }

    #[test]
    fn test_extract_subscribes_panel_api() {
        let text = "some text https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890 more";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should extract panel subscribe URL");
        assert!(results[0].contains("token="));
    }

    #[test]
    fn test_extract_subscribes_short_token() {
        let text = "url https://example.com/api/v1/client/subscribe?token=abc12345 more";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should extract subscribe URL with 8+ char token");
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line() {
        let text = "some text\n192.168.1.1:8080\nmore text\n";
        let results = extract_subscribes(text);
        assert!(!results.is_empty(), "should extract raw IP:PORT lines");
        assert!(results.contains(&"192.168.1.1:8080".to_string()));
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line_with_protocol() {
        let text = "socks5://10.0.0.1:1080\nhttp://192.168.1.100:3128";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 2, "should extract protocol-prefixed proxy lines");
        assert!(results.contains(&"socks5://10.0.0.1:1080".to_string()));
        assert!(results.contains(&"http://192.168.1.100:3128".to_string()));
    }

    #[test]
    fn test_extract_subscribes_base64_inline() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg= ss://YWVzLTI1Ni1nY206cGFzczJAMTI3LjAuMC4xOjgzODg= ss://YWVzLTI1Ni1nY206cGFzczNAMjcuMC4wLjE6ODM4OA==";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw.as_bytes());
        assert!(b64.len() > 80, "base64 string must be 80+ chars to match pattern");
        let text = format!("prefix {} suffix", b64);
        let results = extract_subscribes(&text);
        assert!(!results.is_empty(), "should extract base64 blocks containing proxy data");
    }

    #[test]
    fn test_extract_subscribes_empty() {
        let results = extract_subscribes("just some text without any proxy links");
        assert!(results.is_empty(), "should return empty for text without proxies");
    }

    #[test]
    fn test_extract_subscribes_no_duplicates() {
        let text = "vmess://abc123def456\nvmess://abc123def456";
        let results = extract_subscribes(text);
        assert_eq!(results.len(), 1, "should deduplicate results");
    }

    #[test]
    fn test_extract_subscribes_clash_provider() {
        let text = "proxies: https://example.com/clash/proxy/node1?flag=us";
        let results = extract_subscribes(text);
        assert!(!results.is_empty(), "should extract clash provider URLs");
    }
}
