use crate::error::*;

use super::extract_subscribes;

pub async fn crawl_github(
    client: &reqwest::Client,
    query: &str,
    pages: usize,
    token: &str,
) -> Result<Vec<String>> {
    let encoded: String = percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC).to_string();
    let mut file_urls = Vec::new();

    for page in 1..=pages {
        let url = format!(
            "https://api.github.com/search/code?q={}&sort=indexed&order=desc&per_page=50&page={}",
            encoded, page
        );

        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str()) {
                    file_urls.push(html_url.to_string());
                }
            }
        }
    }

    let mut results = Vec::new();
    for file_url in &file_urls {
        if let Ok(resp) = client.get(file_url).send().await
            && let Ok(text) = resp.text().await {
                results.extend(extract_subscribes(&text));
            }
    }

    let issues_url = format!(
        "https://api.github.com/search/issues?q={}&sort=created&order=desc&per_page=50&page=1",
        encoded
    );
    if let Ok(resp) = client
        .get(&issues_url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        && let Ok(body) = resp.json::<serde_json::Value>().await
            && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str())
                        && let Ok(resp) = client.get(html_url).send().await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                }
            }

    results.sort();
    results.dedup();
    Ok(results)
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

    let mut req = client.get(&url).header("Accept", "application/vnd.github+json");
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let commits_data: Vec<serde_json::Value> = resp.json().await?;
    let mut results = Vec::new();

    for commit in &commits_data {
        let commit_url = match commit.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => continue,
        };

        if let Ok(resp) = client
            .get(commit_url)
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
    let url = format!(
        "https://api.github.com/search/code?q={}+language:text&per_page=50&page=1",
        encoded
    );
    let gist_url = format!(
        "https://api.github.com/gists/public?per_page=50&page=1"
    );

    let mut results = Vec::new();

    // Search gist content via code search
    if let Ok(resp) = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        && let Ok(body) = resp.json::<serde_json::Value>().await
            && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    if let Some(html_url) = item.get("html_url").and_then(|v| v.as_str())
                        && let Ok(resp) = client.get(html_url).send().await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                }
            }

    // Fetch recent public gists and scan their raw content
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
                                    if let Ok(resp) = client.get(raw_url).send().await
                                        && let Ok(text) = resp.text().await {
                                            results.extend(extract_subscribes(&text));
                                        }
                                }
                            }
                        }
                    }
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

    let mut results = Vec::new();
    for topic in topics {
        if topic.is_empty() {
            continue;
        }
        let encoded: String = percent_encoding::utf8_percent_encode(topic, percent_encoding::NON_ALPHANUMERIC).to_string();
        let url = format!(
            "https://api.github.com/search/repositories?q=topic:{}&sort=updated&order=desc&per_page=20&page=1",
            encoded
        );

        if let Ok(resp) = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            && let Ok(body) = resp.json::<serde_json::Value>().await
                && let Some(items) = body.get("items").and_then(|v| v.as_array()) {
                    for item in items {
                        let full_name = match item.get("full_name").and_then(|v| v.as_str()) {
                            Some(n) => n.to_string(),
                            None => continue,
                        };
                        let readme_url = format!(
                            "https://api.github.com/repos/{}/readme",
                            full_name
                        );
                        if let Ok(resp) = client
                            .get(&readme_url)
                            .header("Accept", "application/vnd.github.raw")
                            .header("Authorization", format!("Bearer {}", token))
                            .send()
                            .await
                            && let Ok(text) = resp.text().await {
                                results.extend(extract_subscribes(&text));
                            }
                    }
                }
    }

    results.sort();
    results.dedup();
    results
}
