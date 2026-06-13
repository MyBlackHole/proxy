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

mod cache;
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

pub use cache::PersistStore;
pub use client::build_crawl_client;
pub use depth::{crawl_items_with_depth, crawl_items_with_extractor};
pub use pipeline::{run_pipeline, run_pipeline_stream, PipelineConfig};
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

use tokio::sync::mpsc;

use crate::config::PageCrawlConfig;
use crate::error::*;
use crate::proxy::ProxyNode;

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
    pub async fn crawl(&self, client: &reqwest::Client, _inline_tx: &mpsc::UnboundedSender<ProxyNode>) -> Result<Vec<String>> {
        // _inline_tx unused here because CrawlerSource::crawl is dead code
        let (tx, _) = mpsc::unbounded_channel();
        match self {
            CrawlerSource::Telegram { name, pages } => crawl_telegram(client, name, *pages, tx).await,
            CrawlerSource::GitHubSearch { query, pages, token } => crawl_github(client, query, *pages, token, tx).await,
            CrawlerSource::GitHubUser { username, repo, depth, token } => crawl_github_repo(client, username, repo, *depth, token, tx).await,
            CrawlerSource::Google { query, pages } => crawl_google(client, query, *pages, tx).await,
            CrawlerSource::Yandex { query, pages } => crawl_yandex(client, query, *pages, tx).await,
            CrawlerSource::Twitter { name, num } => crawl_twitter(client, name, *num, tx).await,
            CrawlerSource::CustomPage { url, config } => {
                let urls = vec![url.clone()];
                crawl_pages(client, urls, config, tx).await
            }
            CrawlerSource::GitHubRepo { username, repo_name, commits, token } => {
                crawl_github_repo(client, username, repo_name, *commits, token, tx).await
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
        // Proxy scheme URLs (vmess://, trojan://, etc.) are not extracted as
        // subscribe URLs — they enter the pipeline via content parsing instead.
        let text = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ== trojan://password@1.2.3.4:443?peer=example.com";
        let results = extract_subscribes(text, &mut vec![]);
        assert!(results.is_empty(), "proxy links should not be extracted by extract_subscribes");
    }

    #[test]
    fn test_extract_subscribes_panel_api() {
        let text = "some text https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890 more";
        let results = extract_subscribes(text, &mut vec![]);
        assert_eq!(results.len(), 1, "should extract panel subscribe URL");
        assert!(results[0].contains("token="));
    }

    #[test]
    fn test_extract_subscribes_short_token() {
        let text = "url https://example.com/api/v1/client/subscribe?token=abc12345 more";
        let results = extract_subscribes(text, &mut vec![]);
        assert_eq!(results.len(), 1, "should extract subscribe URL with 8+ char token");
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line() {
        // Raw IP:PORT addresses are not subscribe URLs.
        let text = "some text\n192.168.1.1:8080\nmore text\n";
        let results = extract_subscribes(text, &mut vec![]);
        assert!(results.is_empty(), "raw IP:PORT should not be extracted");
    }

    #[test]
    fn test_extract_subscribes_raw_proxy_line_with_protocol() {
        // Protocol-prefixed proxy addresses are not subscribe URLs.
        let text = "socks5://10.0.0.1:1080\nhttp://192.168.1.100:3128";
        let results = extract_subscribes(text, &mut vec![]);
        assert!(results.is_empty(), "protocol-prefixed proxy addresses should not be extracted");
    }

    #[test]
    fn test_extract_subscribes_base64_inline() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=\nss://YWVzLTI1Ni1nY206cGFzczJAMTI3LjAuMC4xOjgzODg=\nss://YWVzLTI1Ni1nY206cGFzczNAMjcuMC4wLjE6ODM4OA==";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw.as_bytes());
        assert!(b64.len() > 80, "base64 string must be 80+ chars to match pattern");
        let text = format!("prefix {} suffix", b64);
        let mut inline = Vec::new();
        let results = extract_subscribes(&text, &mut inline);
        assert!(results.is_empty(), "base64 decoded proxies should NOT be in subscribe URLs");
        assert!(!inline.is_empty(), "base64 decoded proxies should be in out_inline");
    }

    #[test]
    fn test_extract_subscribes_empty() {
        let results = extract_subscribes("just some text without any proxy links", &mut vec![]);
        assert!(results.is_empty(), "should return empty for text without proxies");
    }

    #[test]
    fn test_extract_subscribes_no_duplicates() {
        let text = "https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890\nhttps://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890";
        let results = extract_subscribes(text, &mut vec![]);
        assert_eq!(results.len(), 1, "should deduplicate results");
    }

    #[test]
    fn test_extract_subscribes_clash_provider() {
        let text = "proxies: https://example.com/clash/proxy/node1?flag=us";
        let results = extract_subscribes(text, &mut vec![]);
        assert!(!results.is_empty(), "should extract clash provider URLs");
    }

    #[test]
    fn test_extract_subscribes_base64_with_subscribe_url() {
        let text = base64::Engine::encode(&base64::engine::general_purpose::STANDARD,
            b"some text https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890 more");
        assert!(text.len() > 80);
        let mut inline = Vec::new();
        let results = extract_subscribes(&text, &mut inline);
        assert!(!results.is_empty(), "base64 decoded subscribe URLs should be returned");
        assert!(results[0].contains("token="));
        assert!(inline.is_empty(), "no proxy links means empty inline");
    }

    #[test]
    fn test_extract_subscribes_base64_mixed() {
        let payload = "https://example.com/sub?token=abcdef1234567890abcdef1234567890\ntrojan://pass@1.2.3.4:443?peer=example.com".to_string();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload.as_bytes());
        assert!(b64.len() > 80);
        let mut inline = Vec::new();
        let results = extract_subscribes(&b64, &mut inline);
        assert!(!results.is_empty(), "should extract subscribe URL from base64");
        assert!(!inline.is_empty(), "should extract trojan proxy from base64");
    }

    #[test]
    fn test_extract_subscribes_inline_clash_yaml() {
        let text = "proxies:\n  - {name: us, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: test}";
        let mut inline = Vec::new();
        let results = extract_subscribes(text, &mut inline);
        assert!(results.is_empty(), "Clash YAML has no subscribe URLs");
        assert!(!inline.is_empty(), "Clash YAML should produce inline proxies");
    }

    #[test]
    fn test_extract_subscribes_inline_plain_proxies() {
        let text = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=\ntrojan://password@1.2.3.4:443?peer=ex.com";
        let mut inline = Vec::new();
        let results = extract_subscribes(text, &mut inline);
        assert!(results.is_empty(), "plain proxy links should not be subscribe URLs");
        assert!(!inline.is_empty(), "plain proxy links should be extracted inline");
    }

    #[test]
    fn test_extract_subscribes_inline_singbox() {
        let text = r#"[
            {"type": "ss", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "test"},
            {"type": "trojan", "server": "5.6.7.8", "server_port": 443, "password": "pass"}
        ]"#;
        let mut inline = Vec::new();
        let results = extract_subscribes(text, &mut inline);
        assert!(results.is_empty(), "sing-box JSON has no subscribe URLs");
        assert!(!inline.is_empty(), "sing-box JSON should produce inline proxies");
    }
}
