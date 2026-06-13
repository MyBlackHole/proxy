use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;


#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub domains: Vec<DomainConfig>,

    #[serde(default)]
    pub crawl: CrawlConfig,

    #[serde(default)]
    pub settings: SettingsConfig,
}


#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    pub name: String,

    #[serde(default)]
    pub sub: Vec<String>,

    #[serde(default)]
    pub domain: String,

    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub rename: String,

    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub coupon: String,

    #[serde(default)]
    pub secure: bool,

    #[serde(default)]
    pub renew: Option<RenewConfig>,
}

fn default_true() -> bool { true }


#[derive(Debug, Clone, Deserialize)]
pub struct RenewConfig {
    #[serde(default)]
    pub plan_id: usize,

    #[serde(default)]
    pub package: String,

    #[serde(default)]
    pub method: usize,

    #[serde(default)]
    pub coupon_code: String,

    #[serde(default)]
    pub accounts: Vec<RenewAccount>,

    #[serde(default)]
    pub chatgpt: ChatGptConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RenewAccount {
    #[serde(default)]
    pub email: String,

    #[serde(default)]
    pub passwd: String,

    #[serde(default)]
    pub ticket: Option<TicketConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TicketConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub autoreset: bool,

    #[serde(default)]
    pub subject: String,

    #[serde(default)]
    pub message: String,

    #[serde(default)]
    pub level: usize,
}

impl Default for TicketConfig {
    fn default() -> Self {
        Self {
            enable: true,
            autoreset: false,
            subject: String::new(),
            message: String::new(),
            level: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ChatGptConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub regex: String,

    #[serde(default)]
    pub operate: String,
}


#[derive(Debug, Clone, Deserialize)]
pub struct CrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub exclude: String,

    #[serde(default = "default_threshold")]
    pub threshold: usize,

    #[serde(default = "default_true")]
    pub singlelink: bool,

    /// Pipeline persistence output directory.  Defaults to ./pipeline_data/
    /// when the pipeline is invoked without a user-specified path.
    #[serde(default)]
    pub persist_dir: Option<PathBuf>,

    #[serde(default)]
    pub config: CrawlItemConfig,

    #[serde(default)]
    pub telegram: TelegramCrawlConfig,

    #[serde(default)]
    pub google: GoogleCrawlConfig,

    #[serde(default)]
    pub yandex: YandexCrawlConfig,

    #[serde(default)]
    pub github: GithubCrawlConfig,

    #[serde(default)]
    pub twitter: TwitterCrawlConfig,

    #[serde(default)]
    pub repositories: Vec<RepoCrawlConfig>,

    /// Discord bot-based channel crawling
    #[serde(default)]
    pub discord: DiscordCrawlConfig,

    /// RSS/Atom feed monitoring
    #[serde(default)]
    pub rss: RssCrawlConfig,

    /// Known proxy aggregation sites
    #[serde(default = "default_proxy_sites")]
    pub proxy_sites: Vec<ProxySiteConfig>,

    /// Reddit proxy subreddit crawling
    #[serde(default)]
    pub reddit: RedditCrawlConfig,

    /// Proxy disclosure API crawling
    #[serde(default = "default_proxy_api")]
    pub proxy_api: ProxyApiCrawlConfig,

    #[serde(default)]
    pub pages: Vec<PageCrawlConfig>,

    /// Max cascade rounds for nested crawling. 0 = disabled.
    /// When > 0, newly discovered subscription URLs from the depth engine
    /// are fed back into the fetch pipeline for additional rounds.
    /// The pipeline's `remaining` depth is set to this value.
    #[serde(default)]
    pub nested_max_rounds: usize,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            exclude: String::new(),
            threshold: 5,
            singlelink: true,
            config: CrawlItemConfig::default(),
            telegram: TelegramCrawlConfig::default(),
            google: GoogleCrawlConfig::default(),
            yandex: YandexCrawlConfig::default(),
            github: GithubCrawlConfig::default(),
            twitter: TwitterCrawlConfig::default(),
            repositories: Vec::new(),
            nested_max_rounds: 3,
            discord: DiscordCrawlConfig::default(),
            rss: RssCrawlConfig::default(),
            persist_dir: None,
            proxy_sites: default_proxy_sites(),
            reddit: RedditCrawlConfig::default(),
            proxy_api: ProxyApiCrawlConfig::default(),
            pages: Vec::new(),
        }
    }
}

fn default_proxy_sites() -> Vec<ProxySiteConfig> {
    vec![
        ProxySiteConfig {
            enable: true,
            url: Some("https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub".into()),
            include: String::new(),
            exclude: String::new(),
        },
    ]
}

fn default_threshold() -> usize { 5 }

// ── New Source: Reddit ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RedditCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Subreddits to crawl for proxy links
    #[serde(default = "default_reddit_subreddits")]
    pub subreddits: Vec<String>,

    /// Max posts to fetch per subreddit
    #[serde(default = "default_reddit_limit")]
    pub limit: usize,

}

impl Default for RedditCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            subreddits: default_reddit_subreddits(),
            limit: 50,
        }
    }
}

fn default_reddit_subreddits() -> Vec<String> {
    vec![
        "proxies".into(),
        "proxyv6".into(),
        "freeproxies".into(),
    ]
}

fn default_reddit_limit() -> usize { 50 }

// ── New Source: Proxy Disclosure APIs ─────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyApiCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

}

impl Default for ProxyApiCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
        }
    }
}

fn default_proxy_api() -> ProxyApiCrawlConfig {
    ProxyApiCrawlConfig::default()
}

// ── New Source: Discord ───────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Discord bot token (required)
    #[serde(default)]
    pub bot_token: String,

    /// Guild (server) ID to crawl
    #[serde(default)]
    pub guild_id: String,

    /// Channel IDs to monitor (empty = all accessible)
    #[serde(default)]
    pub channels: Vec<String>,

    /// Max messages to fetch per channel
    #[serde(default = "default_discord_limit")]
    pub limit: usize,

}

impl Default for DiscordCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            bot_token: String::new(),
            guild_id: String::new(),
            channels: Vec::new(),
            limit: 100,
        }
    }
}

fn default_discord_limit() -> usize { 100 }

// ── New Source: RSS/Atom ───────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RssCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// RSS/Atom feed URLs to monitor
    #[serde(default)]
    pub urls: Vec<String>,

    /// Max entries to process per feed
    #[serde(default = "default_rss_limit")]
    pub limit: usize,

}

impl Default for RssCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            urls: Vec::new(),
            limit: 100,
        }
    }
}

fn default_rss_limit() -> usize { 100 }

// ── New Source: Proxy Aggregation Sites ────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxySiteConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// URL of the proxy aggregation page
    pub url: Option<String>,

    /// Regex pattern to filter proxy content
    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CrawlItemConfig {
    #[serde(default)]
    pub rename: String,

    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,
}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelegramCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_telegram_pages")]
    pub pages: usize,

    /// Enable searching Telegram by keyword across public groups
    #[serde(default = "default_true")]
    pub search_enable: bool,

    /// Keyword to search for in public Telegram groups
    #[serde(default = "default_telegram_search_query")]
    pub search_query: String,

    /// Number of search result pages to crawl
    #[serde(default = "default_telegram_search_pages")]
    pub search_pages: usize,

    #[serde(default)]
    pub exclude: String,

    /// Enable crawling media group/channel history
    #[serde(default = "default_telegram_history_depth")]
    pub history_depth: usize,

    #[serde(default)]
    pub users: HashMap<String, TelegramUserConfig>,
}

fn default_telegram_search_query() -> String {
    "免费节点 订阅 ss:// trojan:// vmess://".to_string()
}

fn default_telegram_history_depth() -> usize { 3 }

fn default_telegram_search_pages() -> usize { 5 }

fn default_telegram_pages() -> usize { 10 }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelegramUserConfig {
    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub config: CrawlItemConfig,

}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct TwitterCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Search Twitter by keyword globally for proxy content
    #[serde(default = "default_true")]
    pub search_enable: bool,

    /// Keyword to search for on Twitter
    #[serde(default = "default_twitter_search_query")]
    pub search_query: String,

    /// Number of tweets to fetch in search results
    #[serde(default = "default_twitter_search_count")]
    pub search_count: usize,

    #[serde(default)]
    pub users: HashMap<String, TwitterUserConfig>,
}

fn default_twitter_search_query() -> String {
    "free proxy v2ray subscription ss://".to_string()
}

fn default_twitter_search_count() -> usize { 50 }

fn default_google_limits() -> usize { 200 }
fn default_yandex_within() -> usize { 3 }
fn default_yandex_pages() -> usize { 10 }
fn default_github_pages() -> usize { 5 }
fn default_github_commits() -> usize { 5 }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TwitterUserConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_twitter_num")]
    pub num: usize,

    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub config: CrawlItemConfig,

}

fn default_twitter_num() -> usize { 50 }


#[derive(Debug, Clone, Default, Deserialize)]
pub struct YandexCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub exclude: String,

    /// Independent search query (if empty, falls back to github.search_topic)
    #[serde(default = "default_yandex_query")]
    pub query: String,

    #[serde(default = "default_yandex_within")]
    pub within: usize,

    #[serde(default = "default_yandex_pages")]
    pub pages: usize,

    #[serde(default)]
    pub notinurl: Vec<String>,

}

fn default_yandex_query() -> String {
    "v2ray clash subscribe token subscription".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PageCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    pub url: Option<String>,

    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

    #[serde(default = "default_true")]
    pub multiple: bool,

    #[serde(default)]
    pub placeholder: String,

    #[serde(default = "default_page_start")]
    pub start: usize,

    #[serde(default = "default_page_end")]
    pub end: usize,

    #[serde(default)]
    pub config: CrawlItemConfig,

    /// Link-following depth (0 = no link following, 1 = follow links from the page, etc.)
    #[serde(default)]
    pub depth: usize,

    /// Number of pages to crawl concurrently (0 or 1 = serial)
    #[serde(default)]
    pub concurrency: usize,

}

fn default_page_start() -> usize { 1 }
fn default_page_end() -> usize { 10 }


#[derive(Debug, Clone, Default, Deserialize)]
pub struct GoogleCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub exclude: String,

    #[serde(default = "default_google_limits")]
    pub limits: usize,

    /// Independent search query (if empty, falls back to github.search_topic)
    #[serde(default = "default_google_query")]
    pub query: String,

    #[serde(default)]
    pub notinurl: Vec<String>,

}

fn default_google_query() -> String {
    "v2ray subscribe clash token subscription free".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubUserConfig {
    #[serde(default)]
    pub sub: String,

}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub username: String,

    #[serde(default)]
    pub repo_name: String,

    #[serde(default = "default_github_commits")]
    pub commits: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_github_pages")]
    pub pages: usize,


    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub spams: Vec<String>,

    /// Default search query for GitHub code search
    #[serde(default = "default_github_search_topic")]
    pub search_topic: String,

    /// GitHub code search query
    #[serde(default = "default_github_query")]
    pub query: String,

    /// Search GitHub Gists for proxy content
    #[serde(default = "default_true")]
    pub search_gists: bool,

    /// Search GitHub Topics matching these keywords
    #[serde(default = "default_github_search_topics")]
    pub search_topics: Vec<String>,

    /// Search repository README files for proxy links
    #[serde(default = "default_true")]
    pub search_readme: bool,

    /// Search file contents in repositories for proxy links
    #[serde(default = "default_true")]
    pub search_files: bool,

    /// GitHub API token (optional). Falls back to GITHUB_TOKEN env var if not set.
    #[serde(default)]
    pub token: String,

    #[serde(default)]
    pub users: HashMap<String, GithubUserConfig>,

    #[serde(default)]
    pub search_repos: Vec<String>,
}

fn default_github_search_topic() -> String {
    "free-proxy".to_string()
}

fn default_github_query() -> String {
    "subscribe?token=".to_string()
}

fn default_github_search_topics() -> Vec<String> {
    vec![
        "free-proxy".into(),
        "v2ray".into(),
        "clash".into(),
        "proxy-list".into(),
        "shadowsocks".into(),
        "trojan".into(),
        "proxies".into(),
        "vpn".into(),
    ]
}


#[derive(Debug, Clone, Deserialize)]
pub struct SettingsConfig {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default)]
    pub socks_proxy: Option<String>,

    #[serde(default = "default_retry")]
    pub retry: usize,

    #[serde(default = "default_test_url")]
    pub test_url: String,

    #[serde(default)]
    pub overwrite: bool,

    #[serde(default)]
    pub invisible: bool,

    /// Path to save raw collected proxy nodes (JSON Lines format).
    /// Each line is a raw ProxyNode parsed from subscriptions/crawling,
    /// saved before health check and dedup. Leave empty to disable.
    #[serde(default)]
    pub raw_output: Option<String>,

    // ── Cache ──

    /// Persistent cache configuration (TTL-based, file-backed)
    #[serde(default)]
    pub cache: CacheSettings,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            concurrency: 64,
            timeout: 30000,
            socks_proxy: None,
            retry: 3,
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            overwrite: false,
            invisible: false,
            raw_output: None,
            cache: CacheSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheSettings {
    /// Enable persistent caching (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Cache directory path (default: "./cache")
    #[serde(default = "default_cache_dir")]
    pub dir: String,

    /// Subscription cache TTL in seconds (default: 60)
    #[serde(default = "default_subscription_ttl")]
    pub subscription_ttl: u64,

    /// Ruleset cache TTL in seconds (default: 21600 = 6h)
    #[serde(default = "default_ruleset_ttl")]
    pub ruleset_ttl: u64,

    /// Serve stale cached data when fetch fails (default: true)
    #[serde(default = "default_true")]
    pub serve_stale: bool,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_cache_dir(),
            subscription_ttl: 60,
            ruleset_ttl: 21600,
            serve_stale: true,
        }
    }
}

fn default_cache_dir() -> String { "./cache".to_string() }
fn default_subscription_ttl() -> u64 { 60 }
fn default_ruleset_ttl() -> u64 { 21600 }

fn default_concurrency() -> usize { 64 }
fn default_timeout() -> u64 { 30000 }
fn default_retry() -> usize { 3 }
fn default_test_url() -> String { "https://www.gstatic.com/generate_204".to_string() }

// ── Pre-processing Pipeline ───────────────────────────────────────────────

impl AppConfig {
    pub fn from_file(path: &str) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        if let Some(ref d) = config.crawl.persist_dir
            && d.as_os_str().is_empty()
        {
            return Err(crate::error::AppError::InvalidConfig(
                "[crawl].persist_dir must not be empty. Omit the field or set it to a valid directory path.".into(),
            ));
        }
        Ok(config)
    }
}
