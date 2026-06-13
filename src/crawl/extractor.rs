use crate::subscribe;

/// Trait for extracting terminal items and sub-source URLs from raw content.
///
/// This is the primary extension point for the shared depth-crawling engine:
/// - `SubscriptionExtractor` handles subscription content (detect_format + extract_links)
/// - `PageLinkExtractor` handles HTML page content (extract_subscribes + extract_page_links)
pub trait ContentExtractor: Send + Sync {
    /// Extract "terminal items" — results collected directly without further processing.
    fn extract_terminal(&self, content: &str) -> Vec<String>;

    /// Extract "sub-source" URLs — these will be re-classified and processed recursively.
    fn extract_sub_sources(&self, content: &str) -> Vec<String>;
}

/// Default extractor for subscription content.
///
/// - `extract_terminal`: detect format + extract proxy links
/// - `extract_sub_sources`: extract sub-source URLs (subscribe URLs, panel links, etc.)
pub struct SubscriptionExtractor;

impl ContentExtractor for SubscriptionExtractor {
    fn extract_terminal(&self, content: &str) -> Vec<String> {
        let fmt = subscribe::detect_format(content.as_bytes());
        subscribe::extract_links(content, fmt)
    }

    fn extract_sub_sources(&self, content: &str) -> Vec<String> {
        super::extract_subscribes(content, &mut vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_extractor_terminal() {
        let extractor = SubscriptionExtractor;
        // vmess links should be extracted as terminal items
        let content = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ==";
        let results = extractor.extract_terminal(content);
        assert!(!results.is_empty(), "should extract vmess links");
        assert!(results[0].starts_with("vmess://"));
    }

    #[test]
    fn test_subscription_extractor_terminal_empty() {
        let extractor = SubscriptionExtractor;
        let results = extractor.extract_terminal("just some text without proxies");
        assert!(results.is_empty(), "no proxies should return empty");
    }

    #[test]
    fn test_subscription_extractor_sub_sources() {
        let extractor = SubscriptionExtractor;
        // Subscription URL should be extracted as sub-source
        let content = "some text https://example.com/api/v1/client/subscribe?token=abcdef1234567890abcdef1234567890 more";
        let results = extractor.extract_sub_sources(content);
        assert_eq!(results.len(), 1, "should extract panel subscribe URL");
        assert!(results[0].contains("token="));
    }

    #[test]
    fn test_subscription_extractor_sub_sources_empty() {
        let extractor = SubscriptionExtractor;
        let results = extractor.extract_sub_sources("plain text without any URLs");
        assert!(results.is_empty(), "no sub-sources should return empty");
    }
}
