use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::watch;
use tokio::sync::Semaphore;

use super::depth;
use super::extractor::ContentExtractor;
use crate::alive;
use crate::parser;
use crate::proxy::EnrichedProxy;
use crate::proxy::ProxyNode;

// ── Data Types ─────────────────────────────────────────────────────────

/// A single URL to fetch and process in the pipeline.
pub struct CrawlTask {
    pub url: String,
    pub remaining: usize,
}

/// Resolved content ready for proxy extraction.
pub struct ContentTask {
    pub content: String,
    pub remaining: usize,
}

/// Configuration for the streaming fetch–extract–validate pipeline.
pub struct PipelineConfig {
    pub fetch_concurrency: usize,
    pub validate_concurrency: usize,
    pub validate_batch_size: usize,
    pub nested_max_rounds: usize,
}

// ── Pipeline Entry Point ───────────────────────────────────────────────

/// Run the streaming three-stage pipeline:
///   1. Fetcher — resolve URLs (HTTP fetch / Base64 decode)
///   2. Extractor — extract proxy strings from content, cascade sub‑URLs
///   3. Validator — batch + health‑check proxy nodes
///
/// Returns alive enriched proxies.  `initial_urls` are pre‑deduplicated
/// URLs from crawlers, domain auto‑register, etc.
pub async fn run_pipeline(
    client: &reqwest::Client,
    config: &PipelineConfig,
    initial_urls: &[String],
) -> Vec<EnrichedProxy> {
    if initial_urls.is_empty() {
        return Vec::new();
    }

    let total_init = initial_urls.len();
    log::info!("[pipeline] starting with {total_init} URLs, nested_max_rounds={}",
        config.nested_max_rounds);

    let work_counter = Arc::new(AtomicIsize::new(0));
    let (shutdown_tx, shutdown_rx0) = watch::channel(false);
    // Unbounded channels — backpressure is applied through semaphores inside each stage.
    let (url_tx,  url_rx)  = mpsc::unbounded_channel();
    let (content_tx, content_rx) = mpsc::unbounded_channel();
    let (proxy_tx, proxy_rx) = mpsc::unbounded_channel();

    // ── Inject initial URLs (add‑before‑sub protocol) ──────────────
    // 1) Increment counter for each initial task.
    // 2) Send the task.
    // 3) After all sent, subtract the "injection token" so that the
    //    counter reflects only in‑flight work.
    for url in initial_urls {
        work_counter.fetch_add(1, Ordering::SeqCst);
        let _ = url_tx.send(CrawlTask {
            url: url.clone(),
            remaining: config.nested_max_rounds,
        });
    }
    // The injection token is the number of initial URLs — we added one
    // per URL, so we subtract the same count after they are all enqueued.
    work_counter.fetch_sub(total_init as isize, Ordering::SeqCst);

    // ── Spawn stages ───────────────────────────────────────────────
    let fetch_conc = config.fetch_concurrency;
    let validate_conc = config.validate_concurrency;
    let batch_size = config.validate_batch_size;

    let fetcher_handle = {
        let client = client.clone();
        let url_rx  = url_rx;
        let content_tx = content_tx;
        let work = Arc::clone(&work_counter);
        let shutdown = shutdown_rx0;
        let sem = Arc::new(Semaphore::new(fetch_conc));
        tokio::spawn(async move {
            fetcher_stage(client, url_rx, content_tx, work, shutdown, sem).await;
        })
    };

    let extractor_handle = {
        let url_tx  = url_tx;
        let content_rx = content_rx;
        let proxy_tx = proxy_tx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            extractor_stage(url_tx, content_rx, proxy_tx, work, shutdown_rx).await;
        })
    };

    let validator_handle = {
        let proxy_rx = proxy_rx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            validator_stage(proxy_rx, batch_size, validate_conc, work, shutdown_rx).await
        })
    };

    // ── Shutdown watcher ───────────────────────────────────────────
    // When work counter hits 0, signal shutdown.
    let watcher_handle = {
        let work = Arc::clone(&work_counter);
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                if work.load(Ordering::SeqCst) <= 0 {
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }
        })
    };

    // ── Collect results ────────────────────────────────────────────
    let enriched = validator_handle.await
        .ok()
        .unwrap_or_default();

    // Ensure shutdown is signaled so stages exit promptly.
    let _ = shutdown_tx.send(true);

    // Await remaining handles (best-effort, they will short-circuit on shutdown).
    let _ = fetcher_handle.await;
    let _ = extractor_handle.await;
    let _ = watcher_handle.await;

    log::info!("[pipeline] finished — {} enriched proxies", enriched.len());
    enriched
}

// ── Fetcher Stage ──────────────────────────────────────────────────────

/// Stage 1: receive `CrawlTask`, classify URL, fetch/resolve content,
/// send `ContentTask` downstream.
async fn fetcher_stage(
    client: reqwest::Client,
    mut url_rx: mpsc::UnboundedReceiver<CrawlTask>,
    content_tx: mpsc::UnboundedSender<ContentTask>,
    work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
    sem: Arc<Semaphore>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::debug!("[pipeline] fetcher received shutdown");
                    break;
                }
            }
            task = url_rx.recv() => {
                let task = match task {
                    Some(t) => t,
                    None => break,   // all senders dropped
                };
                let permit = sem.clone().acquire_owned().await;
                let c = client.clone();
                let tx = content_tx.clone();
                let wc = Arc::clone(&work_counter);
                tokio::spawn(async move {
                    let _permit = permit;
                    let content = match depth::classify(&task.url) {
                        depth::Item::Terminal(..) => Some(task.url.clone()),
                        depth::Item::Resolvable(src) => src.resolve(&c).await,
                    };
                    if let Some(body) = content {
                        let _ = tx.send(ContentTask {
                            content: body,
                            remaining: task.remaining,
                        });
                    }
                    // Task complete — decrement work counter.
                    wc.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
}

// ── Extractor Stage ────────────────────────────────────────────────────

/// Stage 2: receive `ContentTask`, extract terminal proxy strings,
/// cascade sub‑source URLs back into the pipeline.
async fn extractor_stage(
    url_tx: mpsc::UnboundedSender<CrawlTask>,
    mut content_rx: mpsc::UnboundedReceiver<ContentTask>,
    proxy_tx: mpsc::UnboundedSender<ProxyNode>,
    work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::debug!("[pipeline] extractor received shutdown");
                    break;
                }
            }
            task = content_rx.recv() => {
                let task = match task {
                    Some(t) => t,
                    None => break,
                };

                // Parse all terminal proxy links.
                let executor = super::extractor::SubscriptionExtractor;
                let proxies = executor.extract_terminal(&task.content);
                for link in proxies {
                    if let Ok(node) = parser::parse_proxy_url(&link) {
                        let _ = proxy_tx.send(node);
                    }
                }

                // Cascade sub-source URLs (discovery).
                if task.remaining > 1 {
                    let sub_urls = executor.extract_sub_sources(&task.content);
                    for sub in sub_urls {
                        // Add BEFORE send.
                        work_counter.fetch_add(1, Ordering::SeqCst);
                        let _ = url_tx.send(CrawlTask {
                            url: sub,
                            remaining: task.remaining - 1,
                        });
                    }
                }

                // Content task processed.
                work_counter.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

// ── Validator Stage ────────────────────────────────────────────────────

/// Stage 3: receive `ProxyNode`, batch, health‑check, collect alive
/// `EnrichedProxy` values.
async fn validator_stage(
    mut proxy_rx: mpsc::UnboundedReceiver<ProxyNode>,
    batch_size: usize,
    validate_concurrency: usize,
    _work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Vec<EnrichedProxy> {
    let mut batch = Vec::with_capacity(batch_size);
    let mut enriched = Vec::new();

    // Normal processing: collect until channel closes or shutdown is
    // signaled.  On shutdown we drain via try_recv before flushing.
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::debug!("[pipeline] validator received shutdown — draining");
                    // Drain all buffered items without blocking.
                    loop {
                        match proxy_rx.try_recv() {
                            Ok(n) => batch.push(n),
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => {
                                if !batch.is_empty() {
                                    flush_batch(&mut batch, &mut enriched, validate_concurrency).await;
                                }
                                return enriched;
                            }
                        }
                    }
                    // Flush whatever we have and exit.
                    if !batch.is_empty() {
                        flush_batch(&mut batch, &mut enriched, validate_concurrency).await;
                    }
                    return enriched;
                }
            }
            node = proxy_rx.recv() => {
                match node {
                    Some(n) => {
                        batch.push(n);
                        if batch.len() >= batch_size {
                            flush_batch(&mut batch, &mut enriched, validate_concurrency).await;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Channel closed — flush remaining batch.
    if !batch.is_empty() {
        flush_batch(&mut batch, &mut enriched, validate_concurrency).await;
    }

    enriched
}

async fn flush_batch(
    batch: &mut Vec<ProxyNode>,
    enriched: &mut Vec<EnrichedProxy>,
    concurrency: usize,
) {
    if batch.is_empty() {
        return;
    }
    let batch_vec = std::mem::take(batch);
    let results = alive::check_alive_batch(batch_vec, concurrency).await;
    for r in results {
        if r.alive {
            enriched.push(EnrichedProxy::new(r.node, r.latency_ms));
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipeline_empty_input() {
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
        };
        // run_pipeline takes reqwest::Client, but with empty URLs it
        // returns immediately without making any network request.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = run_pipeline(&client, &config, &[]).await;
        assert!(result.is_empty(), "empty input should produce empty output");
    }

    #[tokio::test]
    async fn test_pipeline_initial_urls_single_round() {
        // Direct proxy URLs (terminal items) should be forwarded to the
        // validator stage without any HTTP fetch.  The validator will
        // health-check them; with no server running they will be filtered
        // out, but the pipeline should not panic or hang.
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let urls = vec![
            "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0Ijo0NDMsImFpZCI6IjAiLCJpZCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSJ9".to_string(),
        ];
        let result = run_pipeline(&client, &config, &urls).await;
        // The proxy will fail health check, so result should be empty.
        assert!(result.is_empty(), "unreachable proxy should be filtered out");
    }

    #[test]
    fn test_pipeline_config_defaults() {
        let config = PipelineConfig {
            fetch_concurrency: 4,
            validate_concurrency: 8,
            validate_batch_size: 64,
            nested_max_rounds: 0,
        };
        assert_eq!(config.fetch_concurrency, 4);
        assert_eq!(config.nested_max_rounds, 0);
    }
}
