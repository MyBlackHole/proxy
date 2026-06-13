use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::watch;
use tokio::sync::Semaphore;

use super::cache::PersistStore;
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
    pub url: String,
    pub content: String,
    pub remaining: usize,
}

/// Configuration for the streaming fetch–extract–validate pipeline.
pub struct PipelineConfig {
    pub fetch_concurrency: usize,
    pub validate_concurrency: usize,
    pub validate_batch_size: usize,
    pub nested_max_rounds: usize,
    pub persist_dir: PathBuf,
}

// ── Pipeline Entry Point ───────────────────────────────────────────────

/// Run the three-stage streaming pipeline with disk persistence.
///
/// Each stage persists its output as a side-effect (write-through sink).
/// Persistence failures are logged but never block the pipeline.
pub async fn run_pipeline(
    client: &reqwest::Client,
    config: &PipelineConfig,
    initial_urls: &[String],
) -> Vec<EnrichedProxy> {
    let work_counter = Arc::new(AtomicIsize::new(0));
    let (shutdown_tx, shutdown_rx0) = watch::channel(false);
    let (url_tx, url_rx) = mpsc::unbounded_channel();
    let (content_tx, content_rx) = mpsc::unbounded_channel();
    let (proxy_tx, proxy_rx) = mpsc::unbounded_channel();

    let total_init = initial_urls.len();
    log::info!(
        "[pipeline] starting; {} initial URLs, persist={}",
        total_init, config.persist_dir.display(),
    );

    // ── Spawn stages ───────────────────────────────────────────────
    let fetch_conc = config.fetch_concurrency;
    let validate_conc = config.validate_concurrency;
    let batch_size = config.validate_batch_size;

    let persist_dir = config.persist_dir.clone();

    let fetcher_handle = {
        let client = client.clone();
        let url_rx = url_rx;
        let content_tx = content_tx;
        let work = Arc::clone(&work_counter);
        let shutdown = shutdown_rx0;
        let sem = Arc::new(Semaphore::new(fetch_conc));
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            fetcher_stage(client, url_rx, content_tx, work, shutdown, sem, persist).await;
        })
    };

    let extractor_handle = {
        let url_tx_clone = url_tx.clone();
        let content_rx = content_rx;
        let proxy_tx = proxy_tx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            extractor_stage(url_tx_clone, content_rx, proxy_tx, work, shutdown_rx, persist).await;
        })
    };

    let validator_handle = {
        let proxy_rx = proxy_rx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            validator_stage(proxy_rx, batch_size, validate_conc, work, shutdown_rx, persist).await
        })
    };

    // ── Shutdown watcher ───────────────────────────────────────────
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

    // ── Inject initial URLs ────────────────────────────────────────
    for url in initial_urls {
        work_counter.fetch_add(1, Ordering::SeqCst);
        let _ = url_tx.send(CrawlTask {
            url: url.clone(),
            remaining: config.nested_max_rounds,
        });
    }

    // ── Collect results ────────────────────────────────────────────
    let enriched = validator_handle.await
        .ok()
        .unwrap_or_default();

    let _ = shutdown_tx.send(true);
    let _ = fetcher_handle.await;
    let _ = extractor_handle.await;
    let _ = watcher_handle.await;

    log::info!("[pipeline] finished — {} enriched proxies", enriched.len());
    enriched
}

// ── Streaming Pipeline Entry Point ─────────────────────────────────────

/// Run the three-stage streaming pipeline with external URL receiver.
///
/// External URLs arrive via `external_url_rx`. An internal ingest task
/// forwards them into the pipeline's internal URL channel (Phase 1). When
/// the external rx is exhausted (all crawl sources done), the same task
/// transitions to Phase 2 — monitoring `work_counter` until it reaches 0,
/// then signalling shutdown. This two-phase design avoids the race condition
/// of a separate watcher that could fire before any streaming URL arrives.
pub async fn run_pipeline_stream(
    client: &reqwest::Client,
    config: &PipelineConfig,
    mut external_url_rx: mpsc::UnboundedReceiver<String>,
) -> Vec<EnrichedProxy> {
    let work_counter = Arc::new(AtomicIsize::new(0));
    let (shutdown_tx, shutdown_rx0) = watch::channel(false);
    let (url_tx, url_rx) = mpsc::unbounded_channel();
    let (content_tx, content_rx) = mpsc::unbounded_channel();
    let (proxy_tx, proxy_rx) = mpsc::unbounded_channel();

    log::info!(
        "[pipeline] streaming start; persist={}",
        config.persist_dir.display(),
    );

    // ── Spawn stages (same as run_pipeline) ──────────────────────────
    let fetch_conc = config.fetch_concurrency;
    let validate_conc = config.validate_concurrency;
    let batch_size = config.validate_batch_size;

    let persist_dir = config.persist_dir.clone();

    let fetcher_handle = {
        let client = client.clone();
        let url_rx = url_rx;
        let content_tx = content_tx;
        let work = Arc::clone(&work_counter);
        let shutdown = shutdown_rx0;
        let sem = Arc::new(Semaphore::new(fetch_conc));
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            fetcher_stage(client, url_rx, content_tx, work, shutdown, sem, persist).await;
        })
    };

    let extractor_handle = {
        let url_tx_clone = url_tx.clone();
        let content_rx = content_rx;
        let proxy_tx = proxy_tx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            extractor_stage(url_tx_clone, content_rx, proxy_tx, work, shutdown_rx, persist).await;
        })
    };

    let validator_handle = {
        let proxy_rx = proxy_rx;
        let work = Arc::clone(&work_counter);
        let shutdown_rx = shutdown_tx.subscribe();
        let persist = PersistStore::new(persist_dir.clone());
        tokio::spawn(async move {
            validator_stage(proxy_rx, batch_size, validate_conc, work, shutdown_rx, persist).await
        })
    };

    // ── Ingest-as-watcher task (replaces run_pipeline's separate watcher) ──
    //
    // Phase 1 — forward: read external rx → internal url_tx, write url_log
    // Phase 2 — drain:   external rx exhausted → poll work_counter → shutdown
    //
    // This eliminates the classic streaming race condition where a
    // time-based watcher could fire before the first URL arrives.
    let ingest_work = Arc::clone(&work_counter);
    let ingest_url_tx = url_tx.clone();
    let ingest_shutdown_tx = shutdown_tx.clone();
    let remaining = config.nested_max_rounds;
    let url_log_path = persist_dir.join("collected_urls.txt");

    let ingest_handle = tokio::spawn(async move {
        let mut url_log = match std::fs::File::create(&url_log_path) {
            Ok(f) => Some(f),
            Err(e) => {
                log::warn!("[pipeline] cannot create collected_urls.txt: {e}");
                None
            }
        };

        // Phase 1: Forward external URLs (streaming ingress)
        while let Some(url) = external_url_rx.recv().await {
            ingest_work.fetch_add(1, Ordering::SeqCst);
            let _ = ingest_url_tx.send(CrawlTask {
                url: url.clone(),
                remaining,
            });
            if let Some(ref mut f) = url_log
                && let Err(e) = writeln!(f, "{url}")
            {
                log::warn!("[pipeline] failed to write collected_urls.txt: {e}");
            }
        }
        log::info!("[pipeline] external URL source exhausted; waiting for pipeline drain");

        // Phase 2: External rx exhausted — monitor work_counter
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if ingest_work.load(Ordering::SeqCst) <= 0 {
                let _ = ingest_shutdown_tx.send(true);
                break;
            }
        }
    });

    // ── Collect results ──────────────────────────────────────────────
    let enriched = validator_handle.await
        .ok()
        .unwrap_or_default();

    let _ = shutdown_tx.send(true);
    let _ = fetcher_handle.await;
    let _ = extractor_handle.await;
    let _ = ingest_handle.await;

    log::info!("[pipeline] streaming finished — {} enriched proxies", enriched.len());
    enriched
}

// ── Fetcher Stage ──────────────────────────────────────────────────────

async fn fetcher_stage(
    client: reqwest::Client,
    mut url_rx: mpsc::UnboundedReceiver<CrawlTask>,
    content_tx: mpsc::UnboundedSender<ContentTask>,
    work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
    sem: Arc<Semaphore>,
    persist: PersistStore,
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
                    None => break,
                };
                let permit = sem.clone().acquire_owned().await;
                let c = client.clone();
                let tx = content_tx.clone();
                let url_for_cache = task.url.clone();
                let content = match depth::classify(&task.url) {
                    depth::Item::Terminal(..) => Some(task.url.clone()),
                    depth::Item::Resolvable(src) => src.resolve(&c).await,
                };
                // Persist before dispatching to spawned task.
                if let Some(body) = &content {
                    persist.save_fetched(&url_for_cache, body);
                }
                let url = url_for_cache;
                let wc = work_counter.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(body) = &content {
                        let _ = tx.send(ContentTask {
                            url: url.clone(),
                            content: body.clone(),
                            remaining: task.remaining,
                        });
                    } else {
                        // Resolve returned None — no ContentTask will reach the
                        // extractor, so nobody else can decrement the work
                        // counter for this URL.  Do it here to avoid a hang.
                        wc.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        }
    }
}

// ── Extractor Stage ────────────────────────────────────────────────────

async fn extractor_stage(
    url_tx: mpsc::UnboundedSender<CrawlTask>,
    mut content_rx: mpsc::UnboundedReceiver<ContentTask>,
    proxy_tx: mpsc::UnboundedSender<ProxyNode>,
    work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
    persist: PersistStore,
) {
    let executor = super::extractor::SubscriptionExtractor;
    let mut seen_sub_sources: HashSet<String> = HashSet::new();
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

                let proxies = executor.extract_terminal(&task.content);
                if !proxies.is_empty() {
                    persist.save_extracted(&task.url, &proxies);
                    for link in &proxies {
                        if let Ok(node) = parser::parse_proxy_url(link) {
                            let _ = proxy_tx.send(node);
                        } else {
                            log::warn!("[pipeline] parse_proxy_url failed: {link}");
                        }
                    }
                }

                // Cascade sub-source URLs (dedup'd to avoid duplicate fetches).
                if task.remaining > 1 {
                    let sub_urls = executor.extract_sub_sources(&task.content);
                    for sub in sub_urls {
                        if !seen_sub_sources.insert(sub.clone()) {
                            continue;
                        }
                        work_counter.fetch_add(1, Ordering::SeqCst);
                        let _ = url_tx.send(CrawlTask {
                            url: sub,
                            remaining: task.remaining - 1,
                        });
                    }
                }

                work_counter.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

// ── Validator Stage ────────────────────────────────────────────────────

async fn validator_stage(
    mut proxy_rx: mpsc::UnboundedReceiver<ProxyNode>,
    batch_size: usize,
    validate_concurrency: usize,
    _work_counter: Arc<AtomicIsize>,
    mut shutdown_rx: watch::Receiver<bool>,
    persist: PersistStore,
) -> Vec<EnrichedProxy> {
    let mut batch = Vec::with_capacity(batch_size);
    let mut enriched = Vec::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    log::debug!("[pipeline] validator received shutdown — draining");
                    loop {
                        match proxy_rx.try_recv() {
                            Ok(n) => batch.push(n),
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => {
                                if !batch.is_empty() {
                                    flush_batch(&mut batch, &mut enriched, validate_concurrency, &persist).await;
                                }
                                return enriched;
                            }
                        }
                    }
                    if !batch.is_empty() {
                        flush_batch(&mut batch, &mut enriched, validate_concurrency, &persist).await;
                    }
                    return enriched;
                }
            }
            node = proxy_rx.recv() => {
                match node {
                    Some(n) => {
                        batch.push(n);
                        if batch.len() >= batch_size {
                            flush_batch(&mut batch, &mut enriched, validate_concurrency, &persist).await;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    if !batch.is_empty() {
        flush_batch(&mut batch, &mut enriched, validate_concurrency, &persist).await;
    }

    enriched
}

async fn flush_batch(
    batch: &mut Vec<ProxyNode>,
    enriched: &mut Vec<EnrichedProxy>,
    concurrency: usize,
    persist: &PersistStore,
) {
    if batch.is_empty() {
        return;
    }
    let batch_vec = std::mem::take(batch);
    let results = alive::check_alive_batch(batch_vec, concurrency).await;
    for r in &results {
        if r.alive {
            let ep = EnrichedProxy::new(r.node.clone(), r.latency_ms);
            persist.save_validated(&ep);
            enriched.push(ep);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipeline_empty_input() {
        let dir = tempfile::tempdir().unwrap();
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
            persist_dir: dir.path().to_path_buf(),
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = run_pipeline(&client, &config, &[]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_persists_output() {
        let dir = tempfile::tempdir().unwrap();
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
            persist_dir: dir.path().to_path_buf(),
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = run_pipeline(&client, &config, &[]).await;
        assert!(result.is_empty());
        // Persistence directories are created even with no data.
        assert!(dir.path().join("fetcher").is_dir());
        assert!(dir.path().join("extractor").is_dir());
        assert!(dir.path().join("validator").is_dir());
    }

    #[test]
    fn test_pipeline_config_defaults() {
        let config = PipelineConfig {
            fetch_concurrency: 4,
            validate_concurrency: 8,
            validate_batch_size: 64,
            nested_max_rounds: 0,
            persist_dir: PathBuf::from("/tmp/test"),
        };
        assert_eq!(config.fetch_concurrency, 4);
    }

    #[tokio::test]
    async fn test_pipeline_stream_empty() {
        let dir = tempfile::tempdir().unwrap();
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
            persist_dir: dir.path().to_path_buf(),
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        drop(tx); // No URLs — signal immediate end of stream
        let result = run_pipeline_stream(&client, &config, rx).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_stream_delayed() {
        let dir = tempfile::tempdir().unwrap();
        let config = PipelineConfig {
            fetch_concurrency: 2,
            validate_concurrency: 2,
            validate_batch_size: 50,
            nested_max_rounds: 0,
            persist_dir: dir.path().to_path_buf(),
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let (tx, rx) = mpsc::unbounded_channel();

        let pipeline = run_pipeline_stream(&client, &config, rx);

        // Send a URL after a small delay, simulating streaming input
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            tx.send("https://example.com/sub".into()).ok();
            drop(tx);
        });

        let result = pipeline.await;
        // The URL won't resolve in the test environment (timeout/error),
        // so no enriched proxies are produced — but the pipeline should
        // not hang and should shut down cleanly.
        assert!(result.is_empty());
        handle.await.unwrap();
    }
}
