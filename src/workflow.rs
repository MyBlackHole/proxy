use std::collections::HashMap;

use crate::airport;
use crate::alive;
use crate::config::*;
use crate::convert;
use crate::crawl;
use crate::deduce;
use crate::error::*;
use crate::geoip;
use crate::parser;
use crate::proxy::*;
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

    let client = build_reqwest_client(config.settings.socks_proxy.as_deref())?;

    // 1. Crawl + airport auto-register → raw subscribe URLs
    let crawled_urls = crawl_and_discover(&client, &config).await?;

    // 2. Renewal flow
    process_renewals_all(&client, &config).await?;

    // 3. Domain subscribe-processing → EnrichedProxy (with latency)
    let mut all_enriched = process_domain_subscriptions(&config).await?;

    // 4. Parse + verify crawled subscribe/proxy URLs → EnrichedProxy
    let crawled_enriched = process_crawled_proxies(
        &client, &crawled_urls, &config.settings,
    ).await?;
    all_enriched.extend(crawled_enriched);

    // 5. Global dedup + name conflict resolution on EnrichedProxy
    log::info!("Total enriched proxies before dedup: {}", all_enriched.len());
    all_enriched = deduce::dedup_enriched(all_enriched);
    deduce::resolve_enriched_name_conflicts(&mut all_enriched);
    log::info!("Total enriched proxies after dedup: {}", all_enriched.len());

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
        process_group_smart(&client, group, &all_enriched, &storage).await?;
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

async fn process_domain_subscriptions(
    config: &AppConfig,
) -> Result<Vec<EnrichedProxy>> {
    let mut all_enriched: Vec<EnrichedProxy> = Vec::new();
    for domain in &config.domains {
        match process_domain_enriched(domain, &config.settings).await {
            Ok(proxies) => {
                log::info!("Domain {}: {} alive enriched proxies", domain.name, proxies.len());
                all_enriched.extend(proxies);
            }
            Err(e) => log::error!("Failed to process domain {}: {}", domain.name, e),
        }
    }
    Ok(all_enriched)
}

async fn process_crawled_proxies(
    _client: &reqwest::Client,
    urls: &[String],
    settings: &SettingsConfig,
) -> Result<Vec<EnrichedProxy>> {
    if urls.is_empty() {
        return Ok(Vec::new());
    }
    let proxy = settings.socks_proxy.as_deref();
    log::info!("Processing {} crawled/registered URLs", urls.len());

    let mut crawled_proxies = Vec::new();
    for url in urls {
        if url.contains("://") && !url.starts_with("http://") && !url.starts_with("https://") {
            if let Ok(node) = parser::parse_proxy_url(url) {
                crawled_proxies.push(node);
            }
            continue;
        }
        match subscribe::fetch_and_parse(url, proxy).await {
            Ok(links) => {
                for link in links {
                    if let Ok(node) = parser::parse_proxy_url(&link) {
                        crawled_proxies.push(node);
                    }
                }
            }
            Err(e) => log::debug!("Failed to fetch crawled URL {}: {}", url, e),
        }
    }

    if crawled_proxies.is_empty() {
        return Ok(Vec::new());
    }

    log::info!("Running health check on {} crawled proxies", crawled_proxies.len());
    let results = alive::check_alive_batch(crawled_proxies, settings.concurrency).await;
    let total = results.len();
    let alive: Vec<EnrichedProxy> = results
        .into_iter()
        .filter(|r| r.alive)
        .map(|r| EnrichedProxy::new(r.node, r.latency_ms))
        .collect();
    log::info!("Crawled: {}/{} enriched proxies alive", alive.len(), total);
    Ok(alive)
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

    let gh_token = std::env::var("PUSH_TOKEN").unwrap_or_default();
    let client = client.clone();
    let mut handles: Vec<tokio::task::JoinHandle<Vec<String>>> = Vec::new();

    // ── Telegram channels ──
    if crawl_cfg.telegram.enable {
        for name in crawl_cfg.telegram.users.keys() {
            let client = client.clone();
            let name = name.clone();
            let pages = crawl_cfg.telegram.pages;
            handles.push(tokio::spawn(async move {
                log::info!("Crawling Telegram channel: {}", name);
                match crawl::crawl_telegram(&client, &name, pages).await {
                    Ok(urls) => {
                        log::info!("Telegram {}: {} subscribe URLs", name, urls.len());
                        urls
                    }
                    Err(e) => {
                        log::warn!("Telegram {} crawl failed: {}", name, e);
                        Vec::new()
                    }
                }
            }));
        }

        // Telegram keyword search across public groups
        if crawl_cfg.telegram.search_enable && !crawl_cfg.telegram.search_query.is_empty() {
            let client = client.clone();
            let search_query = crawl_cfg.telegram.search_query.clone();
            let search_pages = crawl_cfg.telegram.search_pages;
            handles.push(tokio::spawn(async move {
                log::info!("Telegram search: {}", search_query);
                match crawl::crawl_telegram_search(&client, &search_query, search_pages).await {
                    Ok(urls) => {
                        log::info!("Telegram search: {} subscribe URLs", urls.len());
                        urls
                    }
                    Err(e) => {
                        log::warn!("Telegram search failed: {}", e);
                        Vec::new()
                    }
                }
            }));
        }
    }

    // ── GitHub code search ──
    if crawl_cfg.github.enable {
        let client = client.clone();
        let query = crawl_cfg.github.query.clone();
        let pages = crawl_cfg.github.pages;
        let users: Vec<(String, String)> = crawl_cfg.github.users.iter()
            .map(|(k, v)| (k.clone(), v.sub.clone()))
            .collect();
        let search_repos: Vec<String> = crawl_cfg.github.search_repos.clone();
        let token = gh_token.clone();
        handles.push(tokio::spawn(async move {
            let mut urls = Vec::new();

            // Global query
            if !query.is_empty() {
                log::info!("Crawling GitHub with query: {}", query);
                match crawl::crawl_github(&client, &query, pages, &token).await {
                    Ok(found) => {
                        log::info!("GitHub query: {} subscribe URLs", found.len());
                        urls.extend(found);
                    }
                    Err(e) => log::warn!("GitHub query crawl failed: {}", e),
                }
            }

            // Per-user repos
            for (username, sub) in &users {
                log::info!("Crawling GitHub user repos: {}", username);
                match crawl::crawl_github_repo(&client, username, sub, 3, &token).await {
                    Ok(found) => {
                        log::info!("GitHub user {}: {} subscribe URLs", username, found.len());
                        urls.extend(found);
                    }
                    Err(e) => log::warn!("GitHub user {} crawl failed: {}", username, e),
                }
            }

            // Specific repos
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

            urls
        }));
    }

    // ── Google search (uses dedicated query if set, falls back to github.search_topic) ──
    if crawl_cfg.google.enable {
        let client = client.clone();
        let google_query = if !crawl_cfg.google.query.is_empty() {
            crawl_cfg.google.query.clone()
        } else {
            crawl_cfg.github.search_topic.clone()
        };
        handles.push(tokio::spawn(async move {
            if google_query.is_empty() {
                return Vec::new();
            }
            log::info!("Crawling Google search");
            let max_pages = 3;
            match crawl::crawl_google(&client, &google_query, max_pages).await {
                Ok(found) => {
                    log::info!("Google: {} subscribe URLs", found.len());
                    found
                }
                Err(e) => {
                    log::warn!("Google crawl failed: {}", e);
                    Vec::new()
                }
            }
        }));
    }

    // ── Yandex search (uses dedicated query if set, falls back to github.search_topic) ──
    if crawl_cfg.yandex.enable {
        let client = client.clone();
        let yandex_query = if !crawl_cfg.yandex.query.is_empty() {
            crawl_cfg.yandex.query.clone()
        } else {
            crawl_cfg.github.search_topic.clone()
        };
        let yandex_pages = crawl_cfg.yandex.pages;
        handles.push(tokio::spawn(async move {
            if yandex_query.is_empty() {
                return Vec::new();
            }
            log::info!("Crawling Yandex search");
            match crawl::crawl_yandex(&client, &yandex_query, yandex_pages).await {
                Ok(found) => {
                    log::info!("Yandex: {} subscribe URLs", found.len());
                    found
                }
                Err(e) => {
                    log::warn!("Yandex crawl failed: {}", e);
                    Vec::new()
                }
            }
        }));
    }

    // ── GitHub gist search ──
    if crawl_cfg.github.enable && crawl_cfg.github.search_gists {
        let token = gh_token.clone();
        let query = crawl_cfg.github.query.clone();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            log::info!("Crawling GitHub gists");
            match crawl::crawl_github_gists(&client, &query, &token).await {
                Ok(found) => {
                    log::info!("GitHub gists: {} subscribe URLs", found.len());
                    found
                }
                Err(e) => {
                    log::warn!("GitHub gist crawl failed: {}", e);
                    Vec::new()
                }
            }
        }));
    }

    // ── GitHub topic search ──
    if crawl_cfg.github.enable && !crawl_cfg.github.search_topics.is_empty() {
        let token = gh_token.clone();
        let topics = crawl_cfg.github.search_topics.clone();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            log::info!("Crawling GitHub topics");
            let found = crawl::crawl_github_topics(&client, &topics, &token).await;
            log::info!("GitHub topics: {} subscribe URLs", found.len());
            found
        }));
    }

    // ── Twitter users + Twitter keyword search ──
    if crawl_cfg.twitter.enable {
        let client = client.clone();
        let users: Vec<(String, bool, usize)> = crawl_cfg.twitter.users.iter()
            .map(|(k, v)| (k.clone(), v.enable, v.num))
            .collect();
        let search_enable = crawl_cfg.twitter.search_enable;
        let search_query = crawl_cfg.twitter.search_query.clone();
        let search_count = crawl_cfg.twitter.search_count;
        handles.push(tokio::spawn(async move {
            let mut urls = Vec::new();

            // Per-user media timeline crawl
            for (name, enabled, num) in &users {
                if !enabled { continue; }
                log::info!("Crawling Twitter user: {}", name);
                match crawl::crawl_twitter(&client, name, *num).await {
                    Ok(found) => {
                        log::info!("Twitter {}: {} subscribe URLs", name, found.len());
                        urls.extend(found);
                    }
                    Err(e) => log::warn!("Twitter {} crawl failed: {}", name, e),
                }
            }

            // Global keyword search
            if search_enable && !search_query.is_empty() {
                log::info!("Crawling Twitter search: {}", search_query);
                match crawl::crawl_twitter_search(&client, &search_query, search_count).await {
                    Ok(found) => {
                        log::info!("Twitter search: {} subscribe URLs", found.len());
                        urls.extend(found);
                    }
                    Err(e) => log::warn!("Twitter search crawl failed: {}", e),
                }
            }

            urls
        }));
    }

    // ── Custom pages ──
    for page in &crawl_cfg.pages {
        if !page.enable { continue; }
        if let Some(url) = &page.url {
            let client = client.clone();
            let url = url.clone();
            let page_cfg = page.clone();
            handles.push(tokio::spawn(async move {
                log::info!("Crawling page: {}", url);
                let urls_list = vec![url.clone()];
                match crawl::crawl_pages(&client, urls_list, &page_cfg).await {
                    Ok(found) => {
                        log::info!("Page {}: {} subscribe URLs", url, found.len());
                        found
                    }
                    Err(e) => {
                        log::warn!("Page {} crawl failed: {}", url, e);
                        Vec::new()
                    }
                }
            }));
        }
    }

    // ── Repository crawl configs ──
    for repo in &crawl_cfg.repositories {
        if !repo.enable { continue; }
        let client = client.clone();
        let username = repo.username.clone();
        let repo_name = repo.repo_name.clone();
        let commits = repo.commits;
        let token = gh_token.clone();
        handles.push(tokio::spawn(async move {
            log::info!("Crawling repo: {}/{}", username, repo_name);
            match crawl::crawl_github_repo(&client, &username, &repo_name, commits, &token).await {
                Ok(found) => {
                    log::info!("Repo {}/{}: {} subscribe URLs", username, repo_name, found.len());
                    found
                }
                Err(e) => {
                    log::warn!("Repo {}/{} crawl failed: {}", username, repo_name, e);
                    Vec::new()
                }
            }
        }));
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
    let email = format!("{}@tempmail.org", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("u"));
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

// ── Domain Subscribe Processing (EnrichedProxy variant) ───────────────────

async fn process_domain_enriched(
    domain: &DomainConfig,
    settings: &SettingsConfig,
) -> Result<Vec<EnrichedProxy>> {
    log::info!("Processing domain: {}", domain.name);
    let proxy = settings.socks_proxy.as_deref();

    let mut raw_links = Vec::new();

    let sub_urls: Vec<&str> = domain.sub.iter().map(|s| s.as_str()).collect();
    if sub_urls.is_empty() && !domain.domain.is_empty() {
        let links = subscribe::fetch_and_parse(&domain.domain, proxy).await?;
        raw_links.extend(links);
    }
    for url in sub_urls {
        log::info!("Fetching subscription: {}", url);
        match subscribe::fetch_and_parse(url, proxy).await {
            Ok(links) => {
                log::info!("Found {} proxy links from {}", links.len(), url);
                raw_links.extend(links);
            }
            Err(e) => log::warn!("Failed to fetch {}: {}", url, e),
        }
    }

    log::info!(
        "Domain {}: {} total proxy links",
        domain.name,
        raw_links.len()
    );

    let mut proxies: Vec<ProxyNode> = raw_links
        .iter()
        .filter_map(|link| parser::parse_proxy_url(link).ok())
        .collect();
    log::info!("Domain {}: {} proxies parsed", domain.name, proxies.len());

    proxies = deduce::dedup_proxies(proxies);
    deduce::resolve_name_conflicts(&mut proxies);

    log::info!(
        "Running health check for domain: {} ({} proxies)",
        domain.name,
        proxies.len()
    );
    let results = alive::check_alive_batch(proxies, settings.concurrency).await;
    let alive_count = results.iter().filter(|r| r.alive).count();
    log::info!(
        "Domain {}: {}/{} proxies alive",
        domain.name,
        alive_count,
        results.len()
    );

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
) -> Result<()> {
    let enriched = if let Some(ref reg) = group.regularize {
        if reg.enable {
            log::info!(
                "Applying GeoIP regularize for group with locate={}, residential={}",
                reg.locate,
                reg.residential
            );
            geoip::regularize_enriched_proxies(client, all_enriched.to_vec(), reg).await?
        } else {
            all_enriched.to_vec()
        }
    } else {
        all_enriched.to_vec()
    };

    // Decide which converter to use based on smart config
    for target_name in group.targets.values() {
        let content = if let Some(ref smart) = group.smart {
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

        if let Some(backend) = storage.get(target_name) {
            backend.write(&content, target_name).await?;
            log::info!("Pushed to '{}'", target_name);
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

    let mut all_enriched = Vec::new();
    for domain in &config.domains {
        log::info!("Check-only: re-validating proxies for domain {}", domain.name);
        match process_domain_enriched(domain, &config.settings).await {
            Ok(proxies) => {
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
        )
        .await?;
        log::info!("Group {} processed", name);
    }

    log::info!("Health check completed");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

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
