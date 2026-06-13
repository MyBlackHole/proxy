//! Per-stage disk persistence for the streaming pipeline (write-through sink).
//!
//! Each stage persists its output to a separate sub-directory as a
//! side-effect.  No data is ever read back during normal pipeline
//! execution — the disk is a pure record of what passed through.

use std::io::Write;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::proxy::EnrichedProxy;

/// Maximum size for `proxies.txt` before rotating (32 MiB).
const ROTATION_BYTES: u64 = 32 * 1024 * 1024;

// ── Persist Store ────────────────────────────────────────────────────────

/// Persistent record of pipeline stage outputs.
///
/// Directory layout:
/// ```text
/// <root>/
///   collected_urls.txt   → all discovered HTTP(S) subscribe URLs (audit trail)
///   fetcher/<sha256(url)>/
///     meta.json         → {"url":"...","size":N}
///     content.txt       → raw fetched body (plain text)
///   extractor/proxies.txt
///                       → one proxy URL per line (plain text)
///   validator/proxies.txt
///                       → addr:port latency_ms (plain text, rotated when > 32 MiB)
/// ```
pub struct PersistStore {
    root: PathBuf,
}

impl PersistStore {
    /// Create or open a persistence directory.
    ///
    /// On creation, intermediate stage directories (`fetcher/`, `extractor/`)
    /// from the previous run are cleaned up. The final output (`proxies.yaml`,
    /// rotated `proxies-*.jsonl`) is preserved.
    pub fn new(root: PathBuf) -> Self {
        let me = Self { root };
        me.cleanup_intermediate();
        me.ensure_dirs();
        me
    }

    /// Remove intermediate stage output from the previous run.
    /// `fetcher/` and `extractor/` are write-only sinks — their data is never
    /// read back, so there's no reason to accumulate it across runs.
    /// Directory creation is handled by `ensure_dirs`.
    fn cleanup_intermediate(&self) {
        for dir in [self.fetcher_dir(), self.extractor_dir()] {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                // Dir may not exist yet on first run — that's fine.
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("[persist] cleanup {}: {e}", dir.display());
                }
            }
        }
    }

    fn fetcher_dir(&self) -> PathBuf { self.root.join("fetcher") }
    fn extractor_dir(&self) -> PathBuf { self.root.join("extractor") }
    fn validator_file(&self) -> PathBuf { self.root.join("validator").join("proxies.txt") }

    fn ensure_dirs(&self) {
        for (label, dir) in [
            ("fetcher", self.fetcher_dir()),
            ("extractor", self.extractor_dir()),
            ("validator", self.root.join("validator")),
        ] {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                log::warn!("[persist] failed to create {label} dir {}: {e}", dir.display());
            }
        }
    }

    fn url_key(url: &str) -> String {
        hex::encode(Sha256::digest(url.as_bytes()))[..32].to_string()
    }

    // ── Fetcher ─────────────────────────────────────────────────────────

    /// Persist a fetched URL + resolved body to disk.
    ///
    /// Creates `<key>/meta.json` (URL + size) and `<key>/content.txt` (raw body).
    pub fn save_fetched(&self, url: &str, content: &str) {
        let dir = self.fetcher_dir().join(Self::url_key(url));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log::warn!("[persist] save_fetched: create dir failed: {e}");
            return;
        }
        let meta = serde_json::json!({ "url": url, "size": content.len() });
        match serde_json::to_vec(&meta) {
            Ok(b) => {
                if let Err(e) = std::fs::write(dir.join("meta.json"), b) {
                    log::warn!("[persist] save_fetched: write meta.json failed: {e}");
                }
            }
            Err(e) => log::warn!("[persist] save_fetched: serialize meta failed: {e}"),
        }
        if let Err(e) = std::fs::write(dir.join("content.txt"), content) {
            log::warn!("[persist] save_fetched: write content.txt failed: {e}");
        }
    }

    /// Return the on-disk path for a fetched URL's body content.
    pub fn fetched_path(&self, url: &str) -> PathBuf {
        self.fetcher_dir().join(Self::url_key(url)).join("content.txt")
    }

    /// Read a previously saved fetched body back from disk.
    ///
    /// Returns `None` if the file doesn't exist or can't be read
    /// (e.g. a different pipeline run cleaned up the fetcher directory).
    pub fn load_fetched(&self, url: &str) -> Option<String> {
        let path = self.fetched_path(url);
        std::fs::read_to_string(&path).ok()
    }

    // ── Extractor ───────────────────────────────────────────────────────

    /// Append extracted proxy URL strings to a file, one URL per line.
    pub fn save_extracted(&self, _url: &str, proxies: &[String]) {
        let path = self.extractor_dir().join("proxies.txt");
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[persist] save_extracted: open failed: {e}");
                return;
            }
        };
        for proxy in proxies {
            if let Err(e) = writeln!(&file, "{proxy}") {
                log::warn!("[persist] save_extracted: write failed: {e}");
                return;
            }
        }
    }

    // ── Validator ───────────────────────────────────────────────────────

    /// Append a validated proxy result as a plain text line: `addr:port latency_ms`.
    /// Rotates the file when it exceeds `ROTATION_BYTES`.
    pub fn save_validated(&self, proxy: &EnrichedProxy) {
        let path = self.validator_file();
        self.maybe_rotate(&path);
        let line = format!("{}:{} {}", proxy.node.host(), proxy.node.port(), proxy.latency_ms);
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|f| {
                use std::io::Write;
                writeln!(&f, "{line}")
            })
        {
            log::warn!("[persist] save_validated: append failed: {e}");
        }
    }

    /// Rotate `proxies.txt` if it exceeds the size limit.
    fn maybe_rotate(&self, path: &std::path::Path) {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::warn!("[persist] check metadata failed: {e}");
                return;
            }
        };
        if metadata.len() < ROTATION_BYTES {
            return;
        }
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let rotated = path.with_file_name(format!("proxies-{ts}.txt"));
        if let Err(e) = std::fs::rename(path, &rotated) {
            log::warn!("[persist] rotate failed: {e}");
        } else {
            log::info!("[persist] rotated proxies.txt → {}", rotated.display());
        }
    }

    // ── Final Result (YAML) ──────────────────────────────────────────

    /// Persist the entire deduped proxy collection as a YAML file.
    pub fn save_final_proxies(&self, proxies: &[EnrichedProxy]) -> Result<(), AppError> {
        let path = self.root.join("proxies.yaml");
        let file = std::fs::File::create(&path)?;
        serde_yaml::to_writer(file, proxies)?;
        log::info!("Saved {} proxies to {}", proxies.len(), path.display());
        Ok(())
    }

    /// Load previously persisted proxy collection from YAML.
    pub fn load_final_proxies(&self) -> Result<Vec<EnrichedProxy>, AppError> {
        let path = self.root.join("proxies.yaml");
        if !path.exists() {
            return Err(AppError::Storage(format!(
                "no proxies.yaml at {} — run 'proxy-collector crawl' first",
                path.display()
            )));
        }
        let file = std::fs::File::open(&path)?;
        let proxies: Vec<EnrichedProxy> = serde_yaml::from_reader(file)?;
        log::info!("Loaded {} proxies from {}", proxies.len(), path.display());
        Ok(proxies)
    }
}
