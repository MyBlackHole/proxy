//! Per-stage disk persistence for the streaming pipeline (write-through sink).
//!
//! Each stage persists its output to a separate sub-directory as a
//! side-effect.  No data is ever read back during normal pipeline
//! execution — the disk is a pure record of what passed through.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::proxy::EnrichedProxy;

// ── Persist Store ────────────────────────────────────────────────────────

/// Persistent record of pipeline stage outputs.
///
/// Directory layout:
/// ```text
/// <root>/
///   fetcher/<sha256(url)>/
///     meta.json         → {"url":"...","size":N}
///     content.txt       → raw fetched body (plain text)
///   extractor/<sha256(url)>.json
///                       → {"url":"...","proxies":[<ProxyNode JSON>,...]}
///   validator/proxies.jsonl
///                       → JSON Lines, one EnrichedProxy per line
/// ```
pub struct PersistStore {
    root: PathBuf,
}

impl PersistStore {
    /// Create or open a persistence directory.
    pub fn new(root: PathBuf) -> Self {
        let me = Self { root };
        me.ensure_dirs();
        me
    }

    fn fetcher_dir(&self) -> PathBuf { self.root.join("fetcher") }
    fn extractor_dir(&self) -> PathBuf { self.root.join("extractor") }
    fn validator_file(&self) -> PathBuf { self.root.join("validator").join("proxies.jsonl") }

    fn ensure_dirs(&self) {
        let _ = std::fs::create_dir_all(self.fetcher_dir());
        let _ = std::fs::create_dir_all(self.extractor_dir());
        let _ = std::fs::create_dir_all(self.root.join("validator"));
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
        let _ = std::fs::create_dir_all(&dir);
        // meta
        if let Ok(b) = serde_json::to_vec(&serde_json::json!({
            "url": url,
            "size": content.len(),
        })) {
            let _ = std::fs::write(dir.join("meta.json"), b);
        }
        // raw body (plain text, no JSON escaping)
        let _ = std::fs::write(dir.join("content.txt"), content);
    }

    // ── Extractor ───────────────────────────────────────────────────────

    /// Persist extracted proxy URL strings for a URL to disk.
    pub fn save_extracted(&self, url: &str, proxies: &[String]) {
        let path = self.extractor_dir().join(format!("{}.json", Self::url_key(url)));
        if let Ok(b) = serde_json::to_vec(&serde_json::json!({
            "url": url,
            "proxies": proxies,
        })) {
            let _ = std::fs::write(&path, b);
        }
    }

    // ── Validator ───────────────────────────────────────────────────────

    /// Append a validated proxy result to the JSON Lines file.
    pub fn save_validated(&self, proxy: &EnrichedProxy) {
        let path = self.validator_file();
        if let Ok(line) = serde_json::to_string(proxy) {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|f| {
                    use std::io::Write;
                    writeln!(&f, "{line}")
                });
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
