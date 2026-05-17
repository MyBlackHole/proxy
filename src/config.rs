use serde::Deserialize;
use std::collections::HashMap;


#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub domains: Vec<DomainConfig>,

    #[serde(default)]
    pub crawl: CrawlConfig,

    #[serde(default)]
    pub groups: HashMap<String, GroupConfig>,

    #[serde(default)]
    pub storage: Option<StorageConfig>,

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
    pub push_to: Vec<String>,

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

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ChatGptConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub regex: String,

    #[serde(default)]
    pub operate: String,
}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct CrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub exclude: String,

    #[serde(default = "default_threshold")]
    pub threshold: usize,

    #[serde(default = "default_true")]
    pub singlelink: bool,

    #[serde(default)]
    pub persist: CrawlPersistConfig,

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

    #[serde(default)]
    pub pages: Vec<PageCrawlConfig>,
}

fn default_threshold() -> usize { 5 }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CrawlPersistConfig {
    #[serde(default)]
    pub subs: String,

    #[serde(default)]
    pub proxies: String,
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
    #[serde(default)]
    pub search_enable: bool,

    /// Keyword to search for in public Telegram groups
    #[serde(default)]
    pub search_query: String,

    /// Number of search result pages to crawl
    #[serde(default = "default_telegram_search_pages")]
    pub search_pages: usize,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub users: HashMap<String, TelegramUserConfig>,
}

fn default_telegram_search_pages() -> usize { 3 }

fn default_telegram_pages() -> usize { 5 }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelegramUserConfig {
    #[serde(default)]
    pub include: String,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub config: CrawlItemConfig,

    #[serde(default)]
    pub push_to: Vec<String>,
}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct TwitterCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Search Twitter by keyword globally for proxy content
    #[serde(default)]
    pub search_enable: bool,

    /// Keyword to search for on Twitter
    #[serde(default)]
    pub search_query: String,

    /// Number of tweets to fetch in search results
    #[serde(default = "default_twitter_search_count")]
    pub search_count: usize,

    #[serde(default)]
    pub users: HashMap<String, TwitterUserConfig>,
}

fn default_twitter_search_count() -> usize { 30 }

fn default_google_limits() -> usize { 100 }
fn default_yandex_within() -> usize { 3 }
fn default_yandex_pages() -> usize { 5 }
fn default_github_pages() -> usize { 2 }
fn default_github_commits() -> usize { 3 }

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

    #[serde(default)]
    pub push_to: Vec<String>,
}

fn default_twitter_num() -> usize { 30 }


#[derive(Debug, Clone, Default, Deserialize)]
pub struct YandexCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default)]
    pub exclude: String,

    /// Independent search query (if empty, falls back to github.search_topic for backwards compat)
    #[serde(default)]
    pub query: String,

    #[serde(default = "default_yandex_within")]
    pub within: usize,

    #[serde(default = "default_yandex_pages")]
    pub pages: usize,

    #[serde(default)]
    pub notinurl: Vec<String>,

    #[serde(default)]
    pub push_to: Vec<String>,
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

    #[serde(default)]
    pub push_to: Vec<String>,
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

    /// Independent search query (if empty, falls back to github.search_topic for backwards compat)
    #[serde(default)]
    pub query: String,

    #[serde(default)]
    pub notinurl: Vec<String>,

    #[serde(default)]
    pub push_to: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScriptCrawlConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubUserConfig {
    #[serde(default)]
    pub sub: String,

    #[serde(default)]
    pub push_to: Vec<String>,
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
    pub push_to: Vec<String>,

    #[serde(default)]
    pub exclude: String,

    #[serde(default)]
    pub spams: Vec<String>,

    #[serde(default)]
    pub search_topic: String,

    #[serde(default)]
    pub query: String,

    /// Search GitHub Gists for proxy content
    #[serde(default)]
    pub search_gists: bool,

    /// Search GitHub Topics matching these keywords
    #[serde(default)]
    pub search_topics: Vec<String>,

    /// Search repository README files for proxy links
    #[serde(default)]
    pub search_readme: bool,

    #[serde(default)]
    pub users: HashMap<String, GithubUserConfig>,

    #[serde(default)]
    pub search_repos: Vec<String>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    pub targets: HashMap<String, String>,

    #[serde(default)]
    pub emoji: bool,

    #[serde(default)]
    pub list: bool,

    #[serde(default)]
    pub regularize: Option<RegularizeConfig>,

    #[serde(default)]
    pub smart: Option<SmartGroupConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmartGroupConfig {
    /// Master switch — enables all smart features
    #[serde(default = "default_true")]
    pub enable: bool,

    // ── Grouping Strategy ──

    /// Auto-create per-region url-test proxy groups
    #[serde(default = "default_true")]
    pub region_groups: bool,

    /// Type for auto groups: "url-test" / "fallback" / "load-balance"
    #[serde(default = "default_smart_auto_type")]
    pub auto_group_type: String,

    /// Whether to include a global fallback group as the ultimate backup
    #[serde(default = "default_true")]
    pub fallback_group: bool,

    /// Whether to include a load-balance group (all proxies, random/round-robin)
    #[serde(default)]
    pub load_balance_group: bool,

    // ── Rule Strategy ──

    /// Whether to generate smart routing rules
    #[serde(default = "default_true")]
    pub generate_rules: bool,

    /// AI services (ChatGPT, Claude, Gemini, Copilot, etc.) → Proxy
    #[serde(default = "default_true")]
    pub ai_rules: bool,

    /// Streaming media (Netflix, Disney+, HBO, YouTube, Bilibili, etc.)
    #[serde(default = "default_true")]
    pub streaming_rules: bool,

    /// Social media (Twitter/X, Instagram, TikTok, Facebook, Telegram)
    #[serde(default = "default_true")]
    pub social_rules: bool,

    /// Gaming (Steam, Epic, PlayStation, Xbox, Nintendo)
    #[serde(default)]
    pub gaming_rules: bool,

    /// Banking & financial sites → Direct
    #[serde(default)]
    pub banking_rules: bool,

    /// Chinese mainland sites & IPs → Direct
    #[serde(default = "default_true")]
    pub direct_rules: bool,

    /// Extra user-defined rules (each line is a Clash rule)
    #[serde(default)]
    pub custom_rules: Vec<String>,
}

impl Default for SmartGroupConfig {
    fn default() -> Self {
        Self {
            enable: true,
            region_groups: true,
            auto_group_type: "url-test".to_string(),
            fallback_group: true,
            load_balance_group: false,
            generate_rules: true,
            ai_rules: true,
            streaming_rules: true,
            social_rules: true,
            gaming_rules: false,
            banking_rules: false,
            direct_rules: true,
            custom_rules: Vec::new(),
        }
    }
}

fn default_smart_auto_type() -> String { "url-test".to_string() }

impl SmartGroupConfig {
    /// Region codes we build auto-groups for (sorted by priority)
    pub fn regions() -> &'static [&'static str] {
        &[
            "HK", "TW", "JP", "KR", "SG", "US", "GB", "DE", "FR",
            "CA", "AU", "IN", "RU", "NL", "SE", "NO", "FI", "DK",
            "CH", "IT", "ES", "AE", "SA", "TH", "VN", "MY", "PH",
            "ID", "MO", "BR", "MX", "AR", "ZA", "TR", "IL", "PL",
            "CZ", "UA", "RO", "GR", "HU", "EG", "NG", "KE",
        ]
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegularizeConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_true")]
    pub locate: bool,

    #[serde(default)]
    pub residential: bool,

    #[serde(default = "default_regularize_bits")]
    pub bits: usize,
}

fn default_regularize_bits() -> usize { 2 }


#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "engine")]
pub enum StorageConfig {
    #[serde(rename = "local")]
    Local {
        items: HashMap<String, LocalStorageItem>,
    },
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LocalStorageItem {
    #[serde(default)]
    pub fileid: Option<String>,
    #[serde(default, alias = "folderid")]
    pub dir: Option<String>,
}


#[derive(Debug, Clone, Default, Deserialize)]
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

    #[serde(default)]
    pub validate_binary: Option<String>,
}

fn default_concurrency() -> usize { 64 }
fn default_timeout() -> u64 { 30000 }
fn default_retry() -> usize { 3 }
fn default_test_url() -> String { "https://www.gstatic.com/generate_204".to_string() }

impl AppConfig {
    pub fn from_file(path: &str) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
