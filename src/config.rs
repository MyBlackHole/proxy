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

    /// Max recursion depth for crawling subscription URLs.
    /// 0 = no recursion (current behavior).
    /// 1 = fetch subscription URLs, extract from their content too.
    /// 2 = two levels deep, etc.
    /// At each level, base64-encoded data is decoded and recursively processed.
    #[serde(default)]
    pub depth: usize,

    /// Max cascade rounds for nested crawling. 0 = disabled (default).
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
            persist: CrawlPersistConfig::default(),
            config: CrawlItemConfig::default(),
            telegram: TelegramCrawlConfig::default(),
            google: GoogleCrawlConfig::default(),
            yandex: YandexCrawlConfig::default(),
            github: GithubCrawlConfig::default(),
            twitter: TwitterCrawlConfig::default(),
            repositories: Vec::new(),
            depth: 0,
            nested_max_rounds: 0,
            discord: DiscordCrawlConfig::default(),
            rss: RssCrawlConfig::default(),
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
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://raw.githubusercontent.com/TheSpeedX/SOCKS-Proxy-List/master/socks5.txt".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://raw.githubusercontent.com/free-proxy-list/free-proxy-list/main/free-proxy-list.txt".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://proxifly-free-proxy-list.p.rapidapi.com/api/v1/proxies?protocol=http&protocol=socks5".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
        },
        ProxySiteConfig {
            enable: true,
            url: Some("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all".into()),
            include: String::new(),
            exclude: String::new(),
            push_to: Vec::new(),
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

    #[serde(default)]
    pub push_to: Vec<String>,
}

impl Default for RedditCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            subreddits: default_reddit_subreddits(),
            limit: 50,
            push_to: Vec::new(),
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

    #[serde(default)]
    pub push_to: Vec<String>,
}

impl Default for ProxyApiCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            push_to: Vec::new(),
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

    #[serde(default)]
    pub push_to: Vec<String>,
}

impl Default for DiscordCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            bot_token: String::new(),
            guild_id: String::new(),
            channels: Vec::new(),
            limit: 100,
            push_to: Vec::new(),
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

    #[serde(default)]
    pub push_to: Vec<String>,
}

impl Default for RssCrawlConfig {
    fn default() -> Self {
        Self {
            enable: true,
            urls: Vec::new(),
            limit: 100,
            push_to: Vec::new(),
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

    #[serde(default)]
    pub push_to: Vec<String>,
}

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

    #[serde(default)]
    pub push_to: Vec<String>,
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

    #[serde(default)]
    pub push_to: Vec<String>,
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

    #[serde(default)]
    pub push_to: Vec<String>,
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

    /// Independent search query (if empty, falls back to github.search_topic)
    #[serde(default = "default_google_query")]
    pub query: String,

    #[serde(default)]
    pub notinurl: Vec<String>,

    #[serde(default)]
    pub push_to: Vec<String>,
}

fn default_google_query() -> String {
    "v2ray subscribe clash token subscription free".to_string()
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
pub struct GroupConfig {
    #[serde(default)]
    pub targets: HashMap<String, String>,

    /// Enable GeoIP-based emoji in region group names (default: false)
    #[serde(default)]
    pub emoji: bool,

    /// Strip existing emoji characters from proxy names before processing
    #[serde(default)]
    pub remove_old_emoji: bool,

    #[serde(default)]
    pub list: bool,

    #[serde(default)]
    pub regularize: Option<RegularizeConfig>,

    #[serde(default)]
    pub smart: Option<SmartGroupConfig>,

    // ── Node Preprocessing Pipeline ──

    /// Pre-processing pipeline applied to proxies before output generation
    #[serde(default)]
    pub preprocess: Option<PreprocessConfig>,

    // ── Custom Proxy Groups (subconverter-style) ──

    /// User-defined proxy groups with regex-based proxy matching
    #[serde(default)]
    pub custom_groups: Vec<CustomGroupConfig>,

    // ── External Rule Sets ──

    /// Remote rule sets downloaded and injected as inline rules or rule-providers
    #[serde(default)]
    pub rulesets: Vec<RulesetConfig>,

    // ── Template Override ──

    /// Custom base Clash YAML template (replaces default header)
    #[serde(default)]
    pub template: Option<TemplateConfig>,
}

/// Custom proxy group — subconverter-style regex-based group membership
///
/// Each group defines a list of `proxies` entries. Each entry is either:
/// - A **regex pattern** (e.g. `"(美|美国|US)"`) — matches proxy names
/// - A **special policy marker** (e.g. `"[]DIRECT"`, `"[]REJECT"`, `"[]PASS"`)
/// - A **group reference** (e.g. `"[]自动选择"`) — references another custom group
#[derive(Debug, Clone, Deserialize)]
pub struct CustomGroupConfig {
    /// Display name of the proxy group
    pub name: String,

    /// Group type: "select", "url-test", "fallback", "load-balance"
    #[serde(default = "default_custom_group_type")]
    pub group_type: String,

    /// Proxy membership: regex patterns (match proxy names) and/or [] directives
    #[serde(default)]
    pub proxies: Vec<String>,

    /// Reference proxy-providers by name (subconverter-style `use:` field)
    ///
    /// When set, the group will include `use:` in its definition instead of
    /// (or in addition to) `proxies:`. Proxy-providers must be defined in
    /// the template or auto-generated.
    #[serde(default)]
    pub use_providers: Vec<String>,

    /// Health-check URL (required for url-test / fallback)
    pub url: Option<String>,

    /// Health-check interval in seconds
    #[serde(default = "default_group_interval")]
    pub interval: u64,

    /// Tolerance in ms (url-test only)
    #[serde(default)]
    pub tolerance: Option<u64>,

    /// Load-balance strategy: "round-robin" or "consistent-hashing"
    #[serde(default)]
    pub strategy: Option<String>,

    /// Lazy loading (don't health-check until first use)
    #[serde(default = "default_true")]
    pub lazy: bool,

    /// Disable UDP for this group
    #[serde(default)]
    pub disable_udp: bool,
}

fn default_custom_group_type() -> String { "select".to_string() }
fn default_group_interval() -> u64 { 300 }

/// An external rule set that gets downloaded and converted to Clash rules
#[derive(Debug, Clone, Deserialize)]
pub struct RulesetConfig {
    /// Target policy group (e.g. "Proxy", "DIRECT", "REJECT")
    pub group: String,

    /// URL or local file path of the rule set file (Surge / Clash / Quantumult X format)
    ///
    /// If the value starts with `http://` or `https://`, it's fetched via HTTP.
    /// Otherwise it's treated as a local file path.
    pub url: String,

    /// Refresh interval in seconds (HTTP rulesets only)
    #[serde(default = "default_ruleset_interval")]
    pub interval: u64,

    /// Explicit behavior: "domain", "ipcidr", "classical" (auto-detect if None)
    #[serde(default)]
    pub behavior: Option<String>,
}

impl RulesetConfig {
    /// Returns true if this ruleset refers to a remote URL
    pub fn is_remote(&self) -> bool {
        self.url.starts_with("http://") || self.url.starts_with("https://")
    }
}

fn default_ruleset_interval() -> u64 { 86400 }

/// Custom base template for Clash output
///
/// The template should be a valid Clash config defining ALL sections.
/// Dynamic sections (`proxies`, `proxy-groups`, `rules`, `rule-providers`,
/// `proxy-providers`) should use `~` (null) placeholders that will be
/// overwritten by the generator. If not specified, the embedded default
/// template (`base/clash_default.yml`) is used — it follows the same
/// full-template design with null placeholders for dynamic content.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TemplateConfig {
    /// Path to a base Clash YAML template file
    ///
    /// Supports two styles:
    /// 1. **YAML injection** (recommended): Placeholder sections use `~`
    ///    (null) — the generator overwrites them with produced content.
    /// 2. **Text substitution** (subconverter-compat): Use `{{proxy}}`,
    ///    `{{proxy_group}}`, `{{rule}}` markers in the raw text — the
    ///    generator replaces them serialized YAML sections.
    ///
    /// If not specified, the built-in `base/clash_default.yml` is used.
    pub base: Option<String>,

    /// Maximum number of inline rules before auto-converting to rule-provider
    #[serde(default = "default_provider_threshold")]
    pub provider_threshold: usize,

    /// Auto-generate proxy-providers from domain subscription sources
    ///
    /// When enabled, proxies are grouped by their source domain name and
    /// each group becomes a proxy-provider entry. Groups can then reference
    /// the provider via the `use:` field instead of listing all proxies inline.
    #[serde(default)]
    pub auto_proxy_providers: bool,

    /// Explicit proxy-provider definitions (subconverter-style)
    ///
    /// Each provider maps to a remote subscription URL. Groups reference
    /// providers by name using the `use:` field.
    #[serde(default)]
    pub proxy_providers: Vec<ProxyProviderConfig>,

    /// Additional Clash config key-value overrides (subconverter-style config add)
    ///
    /// These are merged into the final output AFTER the template is loaded,
    /// allowing you to set or override any Clash config field without
    /// creating a full template file.
    ///
    /// Example in TOML:
    /// ```toml
    /// [groups.free.template.overrides]
    /// port = 9999
    /// "socks-port" = 9998
    /// "external-controller" = "0.0.0.0:9090"
    /// "ipv6" = true
    /// ```
    #[serde(default)]
    pub overrides: Option<std::collections::HashMap<String, toml::Value>>,
}

/// A single proxy provider definition — aligns with subconverter's proxy-provider format.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProviderConfig {
    /// Provider name (referenced by groups via `use:`)
    pub name: String,

    /// Provider type: "http" for remote URL, "file" for local path
    #[serde(default = "default_provider_type")]
    pub provider_type: String,

    /// Remote subscription URL (required for type: http)
    pub url: Option<String>,

    /// Local cache path for the provider data
    #[serde(default = "default_provider_path")]
    pub path: String,

    /// Refresh interval in seconds
    #[serde(default = "default_provider_interval")]
    pub interval: u64,

    /// Health-check configuration
    #[serde(default)]
    pub health_check: Option<ProviderHealthCheck>,
}

fn default_provider_type() -> String { "http".to_string() }
fn default_provider_path() -> String { "./proxy_providers/".to_string() }
fn default_provider_interval() -> u64 { 86400 }

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderHealthCheck {
    /// Enable health check for this provider
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Health check URL
    #[serde(default = "default_health_check_url")]
    pub url: String,

    /// Health check interval in seconds
    #[serde(default = "default_health_check_interval")]
    pub interval: u64,
}

impl Default for ProviderHealthCheck {
    fn default() -> Self {
        Self {
            enable: true,
            url: default_health_check_url(),
            interval: 300,
        }
    }
}

fn default_health_check_url() -> String { "https://www.gstatic.com/generate_204".to_string() }
fn default_health_check_interval() -> u64 { 300 }

fn default_provider_threshold() -> usize { 50 }

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

    #[serde(default)]
    pub validate_binary: Option<String>,

    /// Append Subscription-UserInfo comments to generated output (default: true)
    #[serde(default = "default_true")]
    pub append_userinfo: bool,

    /// Path to save raw collected proxy nodes (JSON Lines format).
    /// Each line is a raw ProxyNode parsed from subscriptions/crawling,
    /// saved before health check and dedup. Leave empty to disable.
    #[serde(default)]
    pub raw_output: Option<String>,

    // ── Global Node Filtering (applied to all groups, before per-group preprocess) ──

    /// Global include filter: keep only proxies whose name matches this regex
    #[serde(default)]
    pub filter_include: String,

    /// Global exclude filter: exclude proxies whose name matches this regex
    #[serde(default)]
    pub filter_exclude: String,

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
            validate_binary: None,
            append_userinfo: true,
            raw_output: None,
            filter_include: String::new(),
            filter_exclude: String::new(),
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

/// Configuration for the proxy pre-processing pipeline.
///
/// Applied after GeoIP regularize but before Clash output generation, in this order:
/// 1. include/exclude regex filter
/// 2. deprecated encryption filter
/// 3. regex rename rules
/// 4. append_proxy_type prefix
/// 5. sort
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PreprocessConfig {
    /// Regex rename rules — each rule replaces proxy name via `regex::Regex`
    #[serde(default)]
    pub rename: Vec<RenameRule>,

    /// If true, prepend the protocol type (e.g. "SS-", "Trojan-") to proxy names
    #[serde(default)]
    pub append_proxy_type: bool,

    /// Sort key: "name", "type", "latency" (default: no sort)
    #[serde(default)]
    pub sort_by: String,

    /// Sort order: "asc" (default) or "desc"
    #[serde(default = "default_sort_order")]
    pub sort_order: String,

    /// Filter out proxies using deprecated/weak encryption
    #[serde(default)]
    pub filter_deprecated: bool,

    /// Keep only proxies whose name matches this regex
    #[serde(default)]
    pub include: String,

    /// Exclude proxies whose name matches this regex (applied after include)
    #[serde(default)]
    pub exclude: String,
}

fn default_sort_order() -> String { "asc".to_string() }

/// A single regex rename rule: `pattern` → `replacement`
#[derive(Debug, Clone, Deserialize)]
pub struct RenameRule {
    /// Regex pattern to match against the proxy name
    pub pattern: String,

    /// Replacement string (supports `$1`, `$2`, etc. capture group references)
    pub replace: String,
}

impl AppConfig {
    pub fn from_file(path: &str) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
