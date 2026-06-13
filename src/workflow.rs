use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::airport;
use crate::alive;
use crate::builder;
use crate::cache;
use crate::config::*;
use crate::convert;
use crate::preprocess;
use crate::validate;

/// Initialize persistent cache from config settings
fn init_cache_from_config(settings: &SettingsConfig) {
    cache::init_cache(
        settings.cache.enabled,
        &settings.cache.dir,
        settings.cache.subscription_ttl,
        settings.cache.ruleset_ttl,
        settings.cache.serve_stale,
    );
}
use crate::crawl;
use crate::deduce;
use crate::error::*;
use crate::geoip;
use crate::parser;
use crate::proxy::*;
use crate::proxy_log::ProxyLogger;
use crate::renewal;
use crate::storage::*;
use crate::subscribe;

// ── Top-level Workflow ────────────────────────────────────────────────────

pub async fn run_workflow(config_path: &str) -> Result<()> {
    let config = AppConfig::from_file(config_path)?;
    log::info!(
        "Loaded config with {} domains, {} groups",
        config.domains.len(),
        config.groups.len()
    );

    init_cache_from_config(&config.settings);

    let client = build_reqwest_client(config.settings.socks_proxy.as_deref())?;
    let direct_client = build_direct_client()?;

    let proxy_log = ProxyLogger::new("proxy_collection.log");
    log::info!("Proxy collection log: proxy_collection.log");

    // 1. Crawl + airport auto-register → raw subscribe URLs
    let crawled_urls = crawl_and_discover(&client, &config).await?;

    // 2. Renewal flow
    process_renewals_all(&client, &config).await?;

    // 3. Domain subscribe-processing → EnrichedProxy (with latency)
    let (domain_enriched, domain_raw) = process_domain_subscriptions(&direct_client, &config).await?;
    proxy_log.log_enriched_batch("domain", &domain_enriched);
    let mut all_enriched = domain_enriched;
    let mut all_raw = domain_raw;

    // 4. Parse + verify crawled subscribe/proxy URLs → EnrichedProxy (direct, no proxy)
    let crawl_depth = config.crawl.depth;
    let (crawled_enriched, crawled_raw) = process_crawled_proxies(
        &direct_client, &crawled_urls, &config.settings, crawl_depth,
    ).await?;
    proxy_log.log_enriched_batch("crawl", &crawled_enriched);
    all_enriched.extend(crawled_enriched);
    all_raw.extend(crawled_raw);

    // 5. Global dedup + name conflict resolution on EnrichedProxy
    log::info!("Total enriched proxies before dedup: {}", all_enriched.len());
    all_enriched = deduce::dedup_enriched(all_enriched);
    deduce::resolve_enriched_name_conflicts(&mut all_enriched);
    log::info!("Total enriched proxies after dedup: {}", all_enriched.len());
    proxy_log.log_enriched_batch("final", &all_enriched);

    // Save raw collected proxy nodes if configured
    if let Some(ref raw_path) = config.settings.raw_output {
        let raw_count = all_raw.len();
        if raw_count > 0 {
            match save_raw_proxies(raw_path, &all_raw) {
                Ok(()) => log::info!("Saved {} raw proxy nodes to {}", raw_count, raw_path),
                Err(e) => log::warn!("Failed to save raw proxy nodes to {}: {}", raw_path, e),
            }
        }
    }

    // 6. Build storage backends
    let storage = match &config.storage {
        Some(s) => create_storage(s)?,
        None => {
            log::info!("No storage configured, skipping output");
            return Ok(());
        }
    };

    // 7. Per-group processing (with smart/legacy converter)
    for (name, group) in &config.groups {
        process_group_smart(&client, group, &all_enriched, &storage, config.settings.append_userinfo, Some(&config.settings)).await?;
        log::info!("Group {} processed", name);
    }

    log::info!("Workflow completed");
    Ok(())
}

async fn crawl_and_discover(
    client: &reqwest::Client,
    config: &AppConfig,
) -> Result<Vec<String>> {
    let proxy = config.settings.socks_proxy.as_deref();
    let mut urls = run_crawlers(client, config).await?;

    for domain in &config.domains {
        if domain.coupon.is_empty() && !domain.secure {
            continue;
        }
        match process_airport_register(client, domain, proxy).await {
            Ok(new_urls) => {
                log::info!("Airport {}: got {} subscribe URLs via auto-reg", domain.name, new_urls.len());
                urls.extend(new_urls);
            }
            Err(e) => log::warn!("Airport {} auto-register skipped: {}", domain.name, e),
        }
    }
    // Dedup crawler + airport URLs to avoid fetching the same URL twice
    urls.sort();
    urls.dedup();
    Ok(urls)
}

async fn process_renewals_all(
    client: &reqwest::Client,
    config: &AppConfig,
) -> Result<()> {
    for domain in &config.domains {
        if let Some(ref renew_cfg) = domain.renew {
            process_renewals(client, domain, renew_cfg).await?;
        }
    }
    Ok(())
}

/// Process crawled/registered URLs into enriched proxies.
///
/// Returns (enriched_alive_proxies, raw_deduped_nodes).
async fn process_crawled_proxies(
    client: &reqwest::Client,
    urls: &[String],
    settings: &SettingsConfig,
    depth: usize,
) -> Result<(Vec<EnrichedProxy>, Vec<ProxyNode>)> {
    if urls.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    log::info!("Processing {} crawled/registered URLs", urls.len());

    let mut crawled_proxies = Vec::new();
    let mut http_urls: Vec<String> = Vec::new();

    for url in urls {
        // Direct proxy URL (non-HTTP scheme like ss://, trojan://, etc.)
        if url.contains("://") && !url.starts_with("http://") && !url.starts_with("https://") {
            if let Ok(node) = parser::parse_proxy_url(url) {
                crawled_proxies.push(node);
            }
            continue;
        }

        // Base64-encoded subscription data extracted from crawled pages
        if !url.contains("://") && url.len() > 20 {
            let stripped: String = url.chars().filter(|c| !c.is_whitespace()).collect();
            if stripped.len() > 20
                && stripped.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                && let Ok(decoded) = subscribe::decode_base64_subscription(&stripped)
            {
                let items = vec![decoded];
                let results = crawl::crawl_items_with_depth(client, &items, depth, settings.concurrency).await;
                if !results.is_empty() {
                    log::info!("Base64 URL (depth={}) decoded into {} proxy links", depth, results.len());
                    for link in results {
                        if let Ok(node) = parser::parse_proxy_url(&link) {
                            crawled_proxies.push(node);
                        }
                    }
                }
                continue;
            }
        }

        // HTTP(S) subscription URL — will be fetched concurrently
        http_urls.push(url.clone());
    }

    // Dedup HTTP URLs to avoid duplicate fetches
    http_urls.sort();
    http_urls.dedup();

    // Concurrently fetch HTTP subscription URLs using shared client (no proxy)
    if !http_urls.is_empty() {
        log::info!("Concurrently fetching {} unique HTTP subscription URLs (depth={})", http_urls.len(), depth);

        // Unified depth crawling via shared engine for all depth levels
        let results = crawl::crawl_items_with_depth(client, &http_urls, depth, settings.concurrency).await;
        log::info!("Depth crawl returned {} proxy links", results.len());
        for link in results {
            if let Ok(node) = parser::parse_proxy_url(&link) {
                crawled_proxies.push(node);
            }
        }
    }

    if crawled_proxies.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Dedup crawled proxies before health check: multiple subscription URLs
    // may return the same proxy nodes
    let before = crawled_proxies.len();
    crawled_proxies = deduce::dedup_proxies(crawled_proxies);
    if crawled_proxies.len() < before {
        log::info!("Dedup'd crawled proxies: {} -> {}", before, crawled_proxies.len());
    }

    // Save raw nodes before health check
    let raw_nodes = crawled_proxies.clone();

    log::info!("Running health check on {} crawled proxies", crawled_proxies.len());
    let results = alive::check_alive_batch(crawled_proxies, settings.concurrency).await;
    let total = results.len();
    let alive: Vec<EnrichedProxy> = results
        .into_iter()
        .filter(|r| r.alive)
        .map(|r| EnrichedProxy::new(r.node, r.latency_ms))
        .collect();
    log::info!("Crawled: {}/{} enriched proxies alive", alive.len(), total);
    Ok((alive, raw_nodes))
}

// ── Crawl Sources (parallel) ─────────────────────────────────────────────

async fn run_crawlers(
    client: &reqwest::Client,
    config: &AppConfig,
) -> Result<Vec<String>> {
    let crawl_cfg = &config.crawl;
    if !crawl_cfg.enable {
        return Ok(Vec::new());
    }

    let gh_token = if !crawl_cfg.github.token.is_empty() {
        crawl_cfg.github.token.clone()
    } else {
        std::env::var("GITHUB_TOKEN").unwrap_or_default()
    };
    let client = client.clone();
    let mut handles: Vec<tokio::task::JoinHandle<Vec<String>>> = Vec::new();

    /// Spawn a crawling task with standard error handling and logging.
    /// Collects the result into `handles` automatically.
    fn spawn_crawler<F, Fut>(
        handles: &mut Vec<tokio::task::JoinHandle<Vec<String>>>,
        client: &reqwest::Client,
        name: &str,
        f: F,
    )
    where
        F: FnOnce(reqwest::Client) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<String>>> + Send + 'static,
    {
        let client = client.clone();
        let name = name.to_string();
        handles.push(tokio::spawn(async move {
            log::info!("Crawling {}", name);
            match f(client).await {
                Ok(found) => {
                    log::info!("{}: {} subscribe URLs", name, found.len());
                    found
                }
                Err(e) => {
                    log::warn!("{} crawl failed: {}", name, e);
                    Vec::new()
                }
            }
        }));
    }

    // ── Telegram ──
    if crawl_cfg.telegram.enable {
        for name in crawl_cfg.telegram.users.keys() {
            let name = name.clone();
            let pages = crawl_cfg.telegram.pages;
            spawn_crawler(&mut handles, &client, &format!("Telegram channel: {}", name), move |client| async move {
                crawl::crawl_telegram(&client, &name, pages).await
            });
        }

        // Telegram keyword search across public groups
        if crawl_cfg.telegram.search_enable && !crawl_cfg.telegram.search_query.is_empty() {
            let search_query = crawl_cfg.telegram.search_query.clone();
            let search_pages = crawl_cfg.telegram.search_pages;
            spawn_crawler(&mut handles, &client, "Telegram search", move |client| async move {
                crawl::crawl_telegram_search(&client, &search_query, search_pages).await
            });
        }
    }

    // ── GitHub code search ──
    if crawl_cfg.github.enable {
        // Global query search
        if !crawl_cfg.github.query.is_empty() {
            let query = crawl_cfg.github.query.clone();
            let pages = crawl_cfg.github.pages;
            let token = gh_token.clone();
            spawn_crawler(&mut handles, &client, "GitHub query", move |client| async move {
                crawl::crawl_github(&client, &query, pages, &token).await
            });
        }

        // Per-user repos
        if !crawl_cfg.github.users.is_empty() {
            let users: Vec<(String, String)> = crawl_cfg.github.users.iter()
                .map(|(k, v)| (k.clone(), v.sub.clone()))
                .collect();
            let token = gh_token.clone();
            spawn_crawler(&mut handles, &client, "GitHub users", move |client| async move {
                let mut urls = Vec::new();
                for (username, sub) in &users {
                    match crawl::crawl_github_repo(&client, username, sub, 3, &token).await {
                        Ok(found) => {
                            log::info!("GitHub user {}: {} subscribe URLs", username, found.len());
                            urls.extend(found);
                        }
                        Err(e) => log::warn!("GitHub user {} crawl failed: {}", username, e),
                    }
                }
                Ok(urls)
            });
        }

        // Specific repos
        if !crawl_cfg.github.search_repos.is_empty() {
            let search_repos: Vec<String> = crawl_cfg.github.search_repos.clone();
            let token = gh_token.clone();
            spawn_crawler(&mut handles, &client, "GitHub repos", move |client| async move {
                let mut urls = Vec::new();
                for repo in &search_repos {
                    let parts: Vec<&str> = repo.split('/').collect();
                    if parts.len() >= 2 {
                        let owner = parts[parts.len() - 2];
                        let repo_name = parts[parts.len() - 1];
                        match crawl::crawl_github_repo(&client, owner, repo_name, 3, &token).await {
                            Ok(found) => {
                                log::info!("GitHub repo {}/{}: {} subscribe URLs", owner, repo_name, found.len());
                                urls.extend(found);
                            }
                            Err(e) => log::warn!("GitHub repo {}/{} crawl failed: {}", owner, repo_name, e),
                        }
                    }
                }
                Ok(urls)
            });
        }
    }

    // ── Google search (uses dedicated query if set, falls back to github.search_topic) ──
    if crawl_cfg.google.enable {
        let google_query = if !crawl_cfg.google.query.is_empty() {
            crawl_cfg.google.query.clone()
        } else {
            crawl_cfg.github.search_topic.clone()
        };
        spawn_crawler(&mut handles, &client, "Google search", move |client| async move {
            if google_query.is_empty() {
                return Ok(Vec::new());
            }
            let max_pages = 3;
            crawl::crawl_google(&client, &google_query, max_pages).await
        });
    }

    // ── Yandex search (uses dedicated query if set, falls back to github.search_topic) ──
    if crawl_cfg.yandex.enable {
        let yandex_query = if !crawl_cfg.yandex.query.is_empty() {
            crawl_cfg.yandex.query.clone()
        } else {
            crawl_cfg.github.search_topic.clone()
        };
        let yandex_pages = crawl_cfg.yandex.pages;
        spawn_crawler(&mut handles, &client, "Yandex search", move |client| async move {
            if yandex_query.is_empty() {
                return Ok(Vec::new());
            }
            crawl::crawl_yandex(&client, &yandex_query, yandex_pages).await
        });
    }

    // ── GitHub gist search ──
    if crawl_cfg.github.enable && crawl_cfg.github.search_gists {
        let query = crawl_cfg.github.query.clone();
        let token = gh_token.clone();
        spawn_crawler(&mut handles, &client, "GitHub gists", move |client| async move {
            crawl::crawl_github_gists(&client, &query, &token).await
        });
    }

    // ── GitHub topic search ──
    if crawl_cfg.github.enable && !crawl_cfg.github.search_topics.is_empty() {
        let topics = crawl_cfg.github.search_topics.clone();
        let token = gh_token.clone();
        spawn_crawler(&mut handles, &client, "GitHub topics", move |client| async move {
            Ok(crawl::crawl_github_topics(&client, &topics, &token).await)
        });
    }

    // ── Twitter ──
    if crawl_cfg.twitter.enable {
        // Per-user media timeline crawl
        if !crawl_cfg.twitter.users.is_empty() {
            let users: Vec<(String, bool, usize)> = crawl_cfg.twitter.users.iter()
                .map(|(k, v)| (k.clone(), v.enable, v.num))
                .collect();
            spawn_crawler(&mut handles, &client, "Twitter users", move |client| async move {
                let mut urls = Vec::new();
                for (name, enabled, num) in &users {
                    if !enabled { continue; }
                    match crawl::crawl_twitter(&client, name, *num).await {
                        Ok(found) => {
                            log::info!("Twitter {}: {} subscribe URLs", name, found.len());
                            urls.extend(found);
                        }
                        Err(e) => log::warn!("Twitter {} crawl failed: {}", name, e),
                    }
                }
                Ok(urls)
            });
        }

        // Global keyword search
        if crawl_cfg.twitter.search_enable && !crawl_cfg.twitter.search_query.is_empty() {
            let search_query = crawl_cfg.twitter.search_query.clone();
            let search_count = crawl_cfg.twitter.search_count;
            spawn_crawler(&mut handles, &client, "Twitter search", move |client| async move {
                crawl::crawl_twitter_search(&client, &search_query, search_count).await
            });
        }
    }

    // ── Custom pages ──
    for page in &crawl_cfg.pages {
        if !page.enable { continue; }
        if let Some(url) = &page.url {
            let url = url.clone();
            let page_cfg = page.clone();
            spawn_crawler(&mut handles, &client, &format!("Page: {}", url), move |client| async move {
                let urls_list = vec![url.clone()];
                crawl::crawl_pages(&client, urls_list, &page_cfg).await
            });
        }
    }

    // ── Repository crawl configs ──
    for repo in &crawl_cfg.repositories {
        if !repo.enable { continue; }
        let username = repo.username.clone();
        let repo_name = repo.repo_name.clone();
        let commits = repo.commits;
        let token = gh_token.clone();
        spawn_crawler(&mut handles, &client, &format!("Repo: {}/{}", username, repo_name), move |client| async move {
            crawl::crawl_github_repo(&client, &username, &repo_name, commits, &token).await
        });
    }

    // ── Discord ──
    if crawl_cfg.discord.enable {
        let discord_cfg = crawl_cfg.discord.clone();
        let settings = config.settings.clone();
        spawn_crawler(&mut handles, &client, "Discord", move |_client| async move {
            Ok(crawl::crawl_discord(&discord_cfg, &settings).await)
        });
    }

    // ── Reddit ──
    if crawl_cfg.reddit.enable {
        let subreddits = crawl_cfg.reddit.subreddits.clone();
        let limit = crawl_cfg.reddit.limit;
        spawn_crawler(&mut handles, &client, "Reddit", move |client| async move {
            crawl::crawl_reddit(&client, &subreddits, limit).await
        });
    }

    // ── Proxy APIs ──
    if crawl_cfg.proxy_api.enable {
        spawn_crawler(&mut handles, &client, "Proxy API", move |client| async move {
            crawl::crawl_proxy_apis(&client).await
        });
    }

    // ── RSS ──
    if crawl_cfg.rss.enable {
        let rss_cfg = crawl_cfg.rss.clone();
        let settings = config.settings.clone();
        spawn_crawler(&mut handles, &client, "RSS", move |_client| async move {
            Ok(crawl::crawl_rss(&rss_cfg, &settings).await)
        });
    }

    // ── Proxy aggregation sites ──
    {
        let enabled_count = crawl_cfg.proxy_sites.iter().filter(|s| s.enable).count();
        log::info!("Crawling {} proxy aggregation sites", enabled_count);
    }
    for site in &crawl_cfg.proxy_sites {
        if !site.enable { continue; }
        let site_cfg = site.clone();
        let site_name = site_cfg.url.clone().unwrap_or_else(|| "unknown".to_string());
        let settings = config.settings.clone();
        spawn_crawler(&mut handles, &client, &format!("Proxy site: {}", site_name), move |_client| async move {
            Ok(crawl::crawl_proxy_site(&site_cfg, &settings).await)
        });
    }

    // ── Collect all results ──
    let mut all_urls: Vec<String> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(urls) => all_urls.extend(urls),
            Err(e) => log::warn!("Crawler task join failed: {}", e),
        }
    }

    all_urls.sort();
    all_urls.dedup();
    Ok(all_urls)
}

// ── Airport Auto-Register + Subscribe ────────────────────────────────────

async fn process_airport_register(
    client: &reqwest::Client,
    domain: &DomainConfig,
    _proxy: Option<&str>,
) -> Result<Vec<String>> {
    let d = domain.domain.trim_end_matches('/');

    // Check if it's SSPanel
    if !airport::is_sspanel(client, d).await {
        log::info!("Domain {} is not SSPanel, skipping auto-register", domain.name);
        return Ok(Vec::new());
    }

    // Generate random email via mailtm or use a generated one
    let email = format!("{}@tempmail.org", uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
    let passwd = uuid::Uuid::new_v4().to_string();

    log::info!("Auto-registering at {} with email={}", domain.name, email);
    match airport::auto_register(client, d, &email, &passwd, "").await {
        Ok(sub_url) => {
            log::info!("Airport {} registered, subscribe URL obtained", domain.name);
            Ok(vec![sub_url])
        }
        Err(e) => {
            log::warn!("Airport {} register failed: {}", domain.name, e);
            Ok(Vec::new())
        }
    }
}

// ── Renewal Flow ──────────────────────────────────────────────────────────

async fn process_renewals(
    client: &reqwest::Client,
    domain: &DomainConfig,
    renew_cfg: &RenewConfig,
) -> Result<()> {
    let d = domain.domain.trim_end_matches('/');

    for account in &renew_cfg.accounts {
        let email_b64 = base64_encode(&account.email);
        let passwd_b64 = base64_encode(&account.passwd);

        log::info!("Renewing account {} at {}", account.email, domain.name);

        match renewal::add_traffic_flow(
            client,
            d,
            &email_b64,
            &passwd_b64,
            renew_cfg.plan_id,
            &renew_cfg.coupon_code,
            renew_cfg.method,
            account.ticket.as_ref(),
        )
        .await
        {
            Ok(result) => log::info!("Renewal success for {}: {}", account.email, result),
            Err(e) => log::warn!("Renewal failed for {}: {}", account.email, e),
        }
    }

    Ok(())
}

// ── Domain Subscribe Processing ──────────────────────────────────────────

/// Fetch and parse subscription links for one domain (no health check).
/// Returns per-domain dedup'd proxy nodes.
async fn fetch_domain_proxies(
    client: &reqwest::Client,
    domain: &DomainConfig,
    settings: &SettingsConfig,
) -> Result<Vec<ProxyNode>> {
    log::info!("Processing domain: {}", domain.name);

    let mut raw_links = Vec::new();

    let sub_urls: Vec<&str> = domain.sub.iter().map(|s| s.as_str()).collect();
    if sub_urls.is_empty() && !domain.domain.is_empty() {
        let links = subscribe::fetch_and_parse_with_client(client, &domain.domain).await?;
        raw_links.extend(links);
    }
    if !sub_urls.is_empty() {
        log::info!("Concurrently fetching {} subscription URLs for domain {}", sub_urls.len(), domain.name);
        let semaphore = Arc::new(Semaphore::new(settings.concurrency));
        let mut handles = Vec::with_capacity(sub_urls.len());
        for url in sub_urls {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let url = url.to_string();
            handles.push(tokio::spawn(async move {
                let _guard = permit;
                log::info!("Fetching subscription: {}", url);
                match subscribe::fetch_and_parse_with_client(&client, &url).await {
                    Ok(links) => {
                        log::info!("Found {} proxy links from {}", links.len(), url);
                        links
                    }
                    Err(e) => {
                        log::warn!("Failed to fetch {}: {}", url, e);
                        Vec::new()
                    }
                }
            }));
        }
        for handle in handles {
            if let Ok(links) = handle.await {
                raw_links.extend(links);
            }
        }
    }

    log::info!("Domain {}: {} total proxy links", domain.name, raw_links.len());

    let mut proxies: Vec<ProxyNode> = raw_links
        .iter()
        .filter_map(|link| parser::parse_proxy_url(link).ok())
        .collect();
    log::info!("Domain {}: {} proxies parsed", domain.name, proxies.len());

    proxies = deduce::dedup_proxies(proxies);
    Ok(proxies)
}

/// Process all domain subscriptions with **global** dedup before health check:
/// proxies shared across domains are only TCP-connected once.
///
/// Returns (enriched_alive_proxies, raw_deduped_nodes).
async fn process_domain_subscriptions(
    client: &reqwest::Client,
    config: &AppConfig,
) -> Result<(Vec<EnrichedProxy>, Vec<ProxyNode>)> {
    // 1. Collect parsed nodes from every domain (no health check yet)
    let mut all_nodes: Vec<(ProxyNode, u32)> = Vec::new();
    for (idx, domain) in config.domains.iter().enumerate() {
        let source_id = (idx + 1) as u32;
        match fetch_domain_proxies(client, domain, &config.settings).await {
            Ok(nodes) => {
                for node in nodes {
                    all_nodes.push((node, source_id));
                }
            }
            Err(e) => log::warn!("Domain {} skipped: {}", domain.name, e),
        }
    }

    if all_nodes.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // 2. Global dedup across all domains
    let mut seen = std::collections::HashSet::new();
    all_nodes.retain(|(node, _)| seen.insert(node.dedup_key()));
    log::info!("{} globally dedup'd proxy nodes across all domains", all_nodes.len());

    // 3. Build source_id map and prepare nodes for health check
    let mut source_map: std::collections::HashMap<DedupKey, u32> = std::collections::HashMap::new();
    let mut nodes_for_check: Vec<ProxyNode> = all_nodes
        .iter()
        .map(|(n, sid)| {
            source_map.entry(n.dedup_key()).or_insert(*sid);
            n.clone()
        })
        .collect();

    let raw_nodes = nodes_for_check.clone();

    // Resolve name conflicts across the global set
    deduce::resolve_name_conflicts(&mut nodes_for_check);

    log::info!("Running batch health check on {} globally dedup'd domain proxies", nodes_for_check.len());
    let results = alive::check_alive_batch(nodes_for_check, config.settings.concurrency).await;
    let alive_count = results.iter().filter(|r| r.alive).count();
    log::info!("{}/{} domain proxies alive", alive_count, results.len());

    let enriched = results
        .into_iter()
        .filter(|r| r.alive)
        .map(|r| {
            let dk = r.node.dedup_key();
            let mut ep = EnrichedProxy::new(r.node, r.latency_ms);
            ep.source_id = source_map.get(&dk).copied().unwrap_or(0);
            ep
        })
        .collect();

    Ok((enriched, raw_nodes))
}

/// Legacy per-domain health-check path (used by `check_alive_only`).
async fn process_domain_enriched(
    client: &reqwest::Client,
    domain: &DomainConfig,
    settings: &SettingsConfig,
) -> Result<Vec<EnrichedProxy>> {
    let mut proxies = fetch_domain_proxies(client, domain, settings).await?;
    deduce::resolve_name_conflicts(&mut proxies);

    log::info!(
        "Running health check for domain: {} ({} proxies)",
        domain.name,
        proxies.len()
    );
    let results = alive::check_alive_batch(proxies, settings.concurrency).await;
    let alive_count = results.iter().filter(|r| r.alive).count();
    log::info!("Domain {}: {}/{} proxies alive", domain.name, alive_count, results.len());

    Ok(results
        .into_iter()
        .filter(|r| r.alive)
        .map(|r| EnrichedProxy::new(r.node, r.latency_ms))
        .collect())
}

// ── Legacy fallback ────────────────────────────────────────────────────────

fn legacy_convert_fallback(enriched: &[EnrichedProxy], target_name: &str) -> Result<String> {
    let plain: Vec<ProxyNode> = enriched.iter().map(|ep| ep.node.clone()).collect();
    log::info!(
        "Legacy converting {} proxies for target '{}'",
        plain.len(),
        target_name
    );
    convert::convert_proxies_to_clash(&plain)
}

// ── Group Processing with Smart Config ────────────────────────────────────

async fn process_group_smart(
    client: &reqwest::Client,
    group: &GroupConfig,
    all_enriched: &[EnrichedProxy],
    storage: &HashMap<String, Box<dyn StorageBackend>>,
    append_userinfo: bool,
    settings: Option<&SettingsConfig>,
) -> Result<()> {
    // Step 0a: Apply global include/exclude filter (from settings)
    let enriched = if let Some(s) = settings {
        let has_filter = !s.filter_include.is_empty() || !s.filter_exclude.is_empty();
        if has_filter {
            let before = all_enriched.len();
            let filtered = preprocess::apply_global_filter(
                all_enriched.to_vec(),
                &s.filter_include,
                &s.filter_exclude,
            );
            log::info!(
                "Global filter: {} → {} proxies ({} removed)",
                before,
                filtered.len(),
                before - filtered.len()
            );
            filtered
        } else {
            all_enriched.to_vec()
        }
    } else {
        all_enriched.to_vec()
    };

    // Step 0b: Remove old emoji from proxy names if configured
    let enriched = if group.remove_old_emoji {
        let before = enriched.len();
        let cleaned = preprocess::remove_old_emoji_from_proxies(enriched);
        log::info!("Removed old emoji from {} proxies", before);
        cleaned
    } else {
        enriched
    };

    // Step 1: GeoIP regularize
    let enriched = if let Some(ref reg) = group.regularize {
        if reg.enable {
            log::info!(
                "Applying GeoIP regularize for group with locate={}, residential={}",
                reg.locate,
                reg.residential
            );
            geoip::regularize_enriched_proxies(client, enriched, reg).await?
        } else {
            enriched
        }
    } else {
        enriched
    };

    // Step 1b: Strip GeoIP emoji from proxies when group.emoji is disabled
    let enriched: Vec<EnrichedProxy> = if !group.emoji {
        enriched.into_iter().map(|mut ep| {
            ep.emoji.clear();
            ep
        }).collect()
    } else {
        enriched
    };

    // Step 2: Apply per-group pre-processing pipeline (rename, filter, sort, etc.)
    let enriched = if let Some(ref pp) = group.preprocess {
        log::info!("Applying pre-processing pipeline to {} proxies", enriched.len());
        preprocess::preprocess_proxies(enriched, pp)
    } else {
        enriched
    };

    // Decide which converter to use
    let has_advanced = !group.custom_groups.is_empty()
        || !group.rulesets.is_empty()
        || group.template.is_some();

    for target_name in group.targets.values() {
        let content = if has_advanced {
            log::info!(
                "Building Clash config with custom groups/rulesets for target '{}'",
                target_name
            );
            let gen_cfg = builder::ClashGenerationConfig {
                enriched: &enriched,
                smart: group.smart.as_ref(),
                custom_groups: &group.custom_groups,
                rulesets: &group.rulesets,
                template: group.template.as_ref(),
                test_url: "https://www.gstatic.com/generate_204",
                domain_proxies: None,
            };
            builder::build_clash_config(client, gen_cfg).await?
        } else if let Some(ref smart) = group.smart {
            if smart.enable {
                log::info!(
                    "Smart converting {} proxies for target '{}'",
                    enriched.len(),
                    target_name
                );
                convert::convert_enriched_to_clash(&enriched, Some(smart))?
            } else {
                legacy_convert_fallback(&enriched, target_name)?
            }
        } else {
            log::info!(
                "Smart converting {} proxies for target '{}' (default config)",
                enriched.len(),
                target_name
            );
            convert::convert_enriched_to_clash(&enriched, Some(&SmartGroupConfig::default()))?
        };

        // Prepend subscription usage info as YAML comments if available
        let content = if append_userinfo && crate::userinfo::has_data() {
            let mut with_comments = String::new();
            with_comments.push_str("# ── Subscription Usage ─────────────────────────────────────\n");
            with_comments.push_str(&crate::userinfo::format_all());
            with_comments.push('\n');
            with_comments.push_str("# ────────────────────────────────────────────────────────────\n");
            with_comments.push_str(&content);
            with_comments
        } else {
            content
        };

        if let Some(backend) = storage.get(target_name) {
            backend.write(&content, target_name).await?;
            log::info!("Pushed to '{}'", target_name);

            // Optional: validate generated config with mihomo -t
            if let Some(s) = settings {
                let binary_path = s.validate_binary.as_deref().map(Path::new);
                if let Ok(bin_path) = validate::find_validate_binary(binary_path) {
                    let temp_dir = std::env::temp_dir()
                        .join(format!("proxy-validate-output-{}", std::process::id()));
                    let _ = std::fs::create_dir_all(&temp_dir);
                    let config_path = temp_dir.join("config.yaml");
                    if std::fs::write(&config_path, &content).is_ok() {
                        match validate::validate_clash_config(&config_path, Some(&bin_path)) {
                            Ok(validate::ValidateResult::Valid { version }) => {
                                log::info!("Config '{}' validated OK ({})", target_name, version);
                            }
                            Ok(other) => {
                                log::warn!("Config '{}' validation unexpected Ok: {:?}", target_name, other);
                            }
                            Err(validate::ValidateResult::Invalid { errors, .. }) => {
                                log::warn!(
                                    "Config '{}' validation FAILED ({} errors): {}",
                                    target_name,
                                    errors.len(),
                                    errors.join("; ")
                                );
                            }
                            Err(other) => {
                                log::warn!("Config '{}' validation error: {:?}", target_name, other);
                            }
                        }
                    }
                    let _ = std::fs::remove_dir_all(&temp_dir);
                }
            }
        } else {
            log::warn!("No storage backend found for target: {}", target_name);
        }
    }
    Ok(())
}

// ── Health-Check Only Mode ────────────────────────────────────────────────

pub async fn check_alive_only(config_path: &str) -> Result<()> {
    let config = AppConfig::from_file(config_path)?;
    log::info!("Running health check only mode");

    init_cache_from_config(&config.settings);
    let direct_client = build_direct_client()?;

    let mut all_enriched = Vec::new();
    for (idx, domain) in config.domains.iter().enumerate() {
        let source_id = (idx + 1) as u32;
        log::info!("Check-only: re-validating proxies for domain {}", domain.name);
        match process_domain_enriched(&direct_client, domain, &config.settings).await {
            Ok(proxies) => {
                let proxies: Vec<EnrichedProxy> = proxies
                    .into_iter()
                    .map(|mut ep| { ep.source_id = source_id; ep })
                    .collect();
                log::info!(
                    "Domain {}: {} proxies alive after re-check",
                    domain.name,
                    proxies.len()
                );
                all_enriched.extend(proxies);
            }
            Err(e) => {
                log::warn!(
                    "Domain {} check error (may be expected in check mode): {}",
                    domain.name,
                    e
                );
            }
        }
    }

    all_enriched = deduce::dedup_enriched(all_enriched);
    deduce::resolve_enriched_name_conflicts(&mut all_enriched);

    let storage = match &config.storage {
        Some(s) => create_storage(s)?,
        None => {
            log::info!("No storage configured, skipping output in check mode");
            return Ok(());
        }
    };
    for (name, group) in &config.groups {
        process_group_smart(
            &build_reqwest_client(config.settings.socks_proxy.as_deref())?,
            group,
            &all_enriched,
            &storage,
            config.settings.append_userinfo,
            Some(&config.settings),
        )
        .await?;
        log::info!("Group {} processed", name);
    }

    log::info!("Health check completed");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn build_direct_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .build()
        .map_err(|e| AppError::InvalidProxy(format!("failed to build client: {}", e)))
}

fn build_reqwest_client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    if let Some(proxy_url) = proxy
        && !proxy_url.is_empty() {
            let p = reqwest::Proxy::all(proxy_url)
                .map_err(|e| AppError::InvalidProxy(format!("invalid proxy: {}", e)))?;
            builder = builder.proxy(p);
        }

    builder.build().map_err(|e| AppError::InvalidProxy(format!("failed to build client: {}", e)))
}

fn base64_encode(input: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose;
    general_purpose::STANDARD.encode(input)
}

/// Save raw proxy nodes to a file in JSON Lines format.
/// Each line is a JSON-serialized ProxyNode.
fn save_raw_proxies(path: &str, nodes: &[ProxyNode]) -> Result<()> {
    use std::io::Write;

    let file_path = std::path::Path::new(path);
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::File::create(file_path)?;
    for node in nodes {
        let line = serde_json::to_string(node)?;
        writeln!(file, "{}", line)?;
    }
    Ok(())
}
