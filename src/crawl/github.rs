use std::sync::Arc;

use crate::error::*;
use tokio::sync::Semaphore;

use super::extract_subscribes;

pub async fn crawl_github(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
    token: &str,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();

    // Phase 1: Concurrently fetch all search result pages
    let file_urls: Vec<String> = {
        let sem = Arc::new(Semaphore::new(5));
        let mut handles = Vec::with_capacity(pages);

        for page in 1..=pages {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let token = token.to_string();
            let encoded = encoded.clone();

            handles.push(tokio::spawn(async move {
                let _guard = permit;
                let url = format!(
                    "https://api.github.com/search/code?q={}&sort=indexed&order=desc&per_page=50&page={}",
                    encoded, page
                );
                log::debug!("[crawl_github] GET search page {}: {}", page, url);

                let resp = match client
                    .get(&url)
                    .header("Accept", "application/vnd.github+json")
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => r,
                    Ok(r) => {
                        log::warn!("[crawl_github] non-success HTTP status {} on page {}", r.status(), page);
                        return Vec::new();
                    }
                    Err(e) => {
                        log::warn!("[crawl_github] HTTP request failed on page {}: {}", page, e);
                        return Vec::new();
                    }
                };

                let body: serde_json::Value = match resp.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("[crawl_github] failed to parse JSON response on page {}: {}", page, e);
                        return Vec::new();
                    }
                };

                let mut urls = Vec::new();
                if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                    for item in items {
                        if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str()) {
                            urls.push(html_url.to_string());
                        }
                    }
                }
                urls
            }));
        }

        let mut all = Vec::new();
        for handle in handles {
            if let Ok(urls) = handle.await {
                all.extend(urls);
            }
        }
        all
    };

    log::info!("[crawl_github] {} file URLs found from code search", file_urls.len());

    // Phase 2: Concurrently fetch all matched file contents
    let results: Vec<String> = {
        if file_urls.is_empty() {
            Vec::new()
        } else {
            let sem = Arc::new(Semaphore::new(10));
            let mut handles = Vec::with_capacity(file_urls.len());

            for file_url in file_urls {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let client = client.clone();

                handles.push(tokio::spawn(async move {
                    let _guard = permit;
                    log::debug!("[crawl_github] GET file: {}", file_url);
                    if let Ok(resp) = client.get(&file_url).send().await
                        && let Ok(text) = resp.text().await
                    {
                        extract_subscribes(&text)
                    } else {
                        Vec::new()
                    }
                }));
            }

            let mut all = Vec::new();
            for handle in handles {
                if let Ok(urls) = handle.await {
                    all.extend(urls);
                }
            }
            all
        }
    };

    // Phase 3: Issues search (single request, typically one page)
    {
        let issues_url = format!(
            "https://api.github.com/search/issues?q={}&sort=created&order=desc&per_page=50&page=1",
            encoded
        );
        log::debug!("[crawl_github] GET issues search: {}", issues_url);

        if let Ok(resp) = client
            .get(&issues_url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            && let Ok(body) = resp.json::<serde_json::Value>().await
                && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                    let issues_sem = Arc::new(Semaphore::new(10));
                    let mut issue_handles = Vec::with_capacity(items.len());

                    for item in items {
                        let permit = issues_sem.clone().acquire_owned().await.unwrap();
                        let client = client.clone();
                        let html_url = match item.get("html_url").and_then(|v| v.as_str()) {
                            Some(u) => u.to_string(),
                            None => continue,
                        };

                        issue_handles.push(tokio::spawn(async move {
                            let _guard = permit;
                            log::debug!("[crawl_github] GET issue: {}", html_url);
                            if let Ok(resp) = client.get(&html_url).send().await
                                && let Ok(text) = resp.text().await
                            {
                                extract_subscribes(&text)
                            } else {
                                Vec::new()
                            }
                        }));
                    }

                    let mut issue_results = results;
                    for handle in issue_handles {
                        if let Ok(urls) = handle.await {
                            issue_results.extend(urls);
                        }
                    }
                    issue_results.sort();
                    issue_results.dedup();
                    return Ok(issue_results);
                }
    }

    let mut final_results = results;
    final_results.sort();
    final_results.dedup();
    Ok(final_results)
}

/// Search file contents in GitHub repositories for proxy subscription URLs.
pub async fn crawl_github_search_files(
    client: &reqwest::Client,
    search_repos: &[String],
    query: &str,
    token: &str,
) -> Vec<String> {
    if search_repos.is_empty() || query.is_empty() {
        return Vec::new();
    }

    let encoded: String =
        percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let mut results = Vec::new();

    for repo_full in search_repos {
        let search_url = format!(
            "https://api.github.com/search/code?q={}+repo:{}&per_page=50&page=1",
            encoded, repo_full
        );

        let resp = match client
            .get(&search_url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::warn!("[github_search_files] repo {} returned HTTP {}", repo_full, r.status());
                continue;
            }
            Err(e) => {
                log::warn!("[github_search_files] failed to search repo {}: {}", repo_full, e);
                continue;
            }
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[github_search_files] failed to parse response for {}: {}", repo_full, e);
                continue;
            }
        };

        let items = match body.get("items").and_then(|v| v.as_array()) {
            Some(i) => i,
            None => continue,
        };

        for item in items {
            let html_url = match item.get("html_url").and_then(|v| v.as_str()) {
                Some(u) => u.to_string(),
                None => continue,
            };

            if let Ok(resp) = client.get(&html_url).send().await
                && let Ok(text) = resp.text().await
            {
                results.extend(extract_subscribes(&text));
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

pub async fn crawl_github_repo(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    commits: usize,
    token: &str,
) -> Result<Vec<String>> {
    let per_page = commits.max(1);
    let url = format!(
        "https://api.github.com/repos/{}/{}/commits?per_page={}",
        owner, repo, per_page
    );
    log::debug!("[crawl_github_repo] GET commits list: {}", url);

    let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let commits_data: Vec<serde_json::Value> = resp.json().await?;
    if commits_data.is_empty() {
        return Ok(Vec::new());
    }

    // Concurrently fetch each commit detail
    let sem = Arc::new(Semaphore::new(10));
    let mut handles = Vec::with_capacity(commits_data.len());

    for commit in commits_data {
        let commit_url = match commit.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => continue,
        };
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();

        handles.push(tokio::spawn(async move {
            let _guard = permit;
            log::debug!("[crawl_github_repo] GET commit: {}", commit_url);
            let mut results = Vec::new();
            if let Ok(resp) = client
                .get(&commit_url)
                .header("Accept", "application/vnd.github+json")
                .send()
                .await
                && let Ok(body) = resp.json::<serde_json::Value>().await
                    && let Some(files) = body.get("files").and_then(|v| v.as_array()) {
                        for file in files {
                            if let Some(patch) = file.get("patch").and_then(|v| v.as_str()) {
                                results.extend(extract_subscribes(patch));
                            }
                        }
                    }
            results
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(mut urls) = handle.await {
            results.append(&mut urls);
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Search GitHub Gists for proxy-related content
pub async fn crawl_github_gists(
    client: &reqwest::Client,
    query: &str,
    token: &str,
) -> Result<Vec<String>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();

    // Phase 1: Fetch gist URLs from code search + public gists list (two independent API calls)
    let (code_urls, gist_urls) = tokio::join!(
        async {
            let url = format!(
                "https://api.github.com/search/code?q={}+language:text&per_page=50&page=1",
                encoded
            );
            log::debug!("[crawl_github_gists] GET code search: {}", url);
            let mut urls = Vec::new();
            if let Ok(resp) = client
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                && let Ok(body) = resp.json::<serde_json::Value>().await
                    && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                        for item in items {
                            if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str()) {
                                urls.push(html_url.to_string());
                            }
                        }
                    }
            urls
        },
        async {
            let gist_url = "https://api.github.com/gists/public?per_page=50&page=1".to_string();
            log::debug!("[crawl_github_gists] GET public gists: {}", gist_url);
            let mut urls = Vec::new();
            if let Ok(resp) = client
                .get(&gist_url)
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                && let Ok(gists) = resp.json::<Vec<serde_json::Value>>().await {
                    for gist in &gists {
                        if let Some(files) = gist.get("files").and_then(|v| v.as_object()) {
                            for (_name, file) in files {
                                if let Some(raw_url) = file.get("raw_url").and_then(|v| v.as_str()) {
                                    if raw_url.contains(".yaml") || raw_url.contains(".yml")
                                        || raw_url.contains(".txt") || raw_url.contains(".conf")
                                        || raw_url.contains("config") || raw_url.contains("proxy")
                                    {
                                        urls.push(raw_url.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            urls
        }
    );

    // Phase 2: Concurrently fetch all collected gist URLs
    let all_urls: Vec<String> = code_urls.into_iter().chain(gist_urls).collect();
    if all_urls.is_empty() {
        return Ok(Vec::new());
    }

    log::info!("[crawl_github_gists] {} gist URLs to fetch", all_urls.len());

    let sem = Arc::new(Semaphore::new(10));
    let mut handles = Vec::with_capacity(all_urls.len());

    for gist_url in all_urls {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let _guard = permit;
            log::debug!("[crawl_github_gists] GET gist: {}", gist_url);
            if let Ok(resp) = client.get(&gist_url).send().await
                && let Ok(text) = resp.text().await {
                    extract_subscribes(&text)
                } else {
                    Vec::new()
                }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(urls) = handle.await {
            results.extend(urls);
        }
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Search GitHub topics for proxy-related repositories, scan their READMEs
pub async fn crawl_github_topics(
    client: &reqwest::Client,
    topics: &[String],
    token: &str,
) -> Vec<String> {
    if topics.is_empty() {
        return Vec::new();
    }

    // Phase 1: Concurrently search for repos under each topic
    let topic_sem = Arc::new(Semaphore::new(5));
    let mut topic_handles = Vec::with_capacity(topics.len());

    for topic in topics {
        if topic.is_empty() {
            continue;
        }
        let permit = topic_sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let token = token.to_string();
        let topic = topic.clone();

        topic_handles.push(tokio::spawn(async move {
            let _guard = permit;
            let encoded: String = percent_encoding::utf8_percent_encode(&topic, percent_encoding::NON_ALPHANUMERIC).to_string();
            let url = format!(
                "https://api.github.com/search/repositories?q=topic:{}&sort=updated&order=desc&per_page=20&page=1",
                encoded
            );
            log::debug!("[crawl_github_topics] GET topic search: {}", url);

            let mut repos = Vec::new();
            if let Ok(resp) = client
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                && let Ok(body) = resp.json::<serde_json::Value>().await
                    && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                        for item in items {
                            if let Some(full_name) = item.get("full_name").and_then(|v| v.as_str()) {
                                repos.push(full_name.to_string());
                            }
                        }
                    }
            repos
        }));
    }

    // Collect all repo names first
    let mut repo_names = Vec::new();
    for handle in topic_handles {
        if let Ok(repos) = handle.await {
            repo_names.extend(repos);
        }
    }

    if repo_names.is_empty() {
        return Vec::new();
    }

    log::info!("[crawl_github_topics] {} repos found across {} topics", repo_names.len(), topics.len());

    // Phase 2: Concurrently fetch README for each repo
    let readme_sem = Arc::new(Semaphore::new(10));
    let mut readme_handles = Vec::with_capacity(repo_names.len());

    for full_name in repo_names {
        let permit = readme_sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let token = token.to_string();

        readme_handles.push(tokio::spawn(async move {
            let _guard = permit;
            let readme_url = format!(
                "https://api.github.com/repos/{}/readme",
                full_name
            );
            log::debug!("[crawl_github_topics] GET readme: {}", readme_url);
            if let Ok(resp) = client
                .get(&readme_url)
                .header("Accept", "application/vnd.github.raw")
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                && let Ok(text) = resp.text().await
            {
                extract_subscribes(&text)
            } else {
                Vec::new()
            }
        }));
    }

    let mut results = Vec::new();
    for handle in readme_handles {
        if let Ok(urls) = handle.await {
            results.extend(urls);
        }
    }

    results.sort();
    results.dedup();
    results
}
