use chrono::Local;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::alive::HealthResult;
use crate::proxy::{EnrichedProxy, ProxyNode};

/// Structured proxy collection logger.
///
/// Writes JSON Lines (one JSON object per line) to a log file,
/// recording every proxy collected, its health check result, and
/// its final enriched state. Useful for auditing, analysis, and
/// debugging what was collected.
///
/// Thread-safe via internal Mutex — safe to share across tasks.
pub struct ProxyLogger {
    file: Mutex<Option<std::fs::File>>,
}

impl ProxyLogger {
    /// Creates a new `ProxyLogger` writing to `path`.
    ///
    /// If the path cannot be opened (parent missing, permissions, etc.),
    /// a warning is logged and all subsequent writes are silently dropped.
    pub fn new(path: &str) -> Self {
        let path = PathBuf::from(path);
        let file = open_log_file(&path);
        Self {
            file: Mutex::new(file),
        }
    }

    /// Creates a disabled logger that silently drops all writes.
    pub fn disabled() -> Self {
        Self {
            file: Mutex::new(None),
        }
    }

    /// Log a freshly parsed proxy node (before health check).
    pub fn log_parsed(&self, source: &str, node: &ProxyNode) {
        let entry = json!({
            "ts": Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            "event": "parsed",
            "source": source,
            "type": node.proxy_type(),
            "name": node.name(),
            "host": node.host(),
            "port": node.port(),
        });
        self.write_entry(&entry.to_string());
    }

    /// Log a batch of parsed proxy nodes.
    pub fn log_parsed_batch(&self, source: &str, nodes: &[ProxyNode]) {
        for node in nodes {
            self.log_parsed(source, node);
        }
    }

    /// Log a health check result (alive or dead).
    pub fn log_health(&self, source: &str, result: &HealthResult) {
        let entry = json!({
            "ts": Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            "event": "health_check",
            "source": source,
            "type": result.node.proxy_type(),
            "name": result.node.name(),
            "host": result.node.host(),
            "port": result.node.port(),
            "alive": result.alive,
            "latency_ms": result.latency_ms,
        });
        self.write_entry(&entry.to_string());
    }

    /// Log a batch of health check results.
    pub fn log_health_batch(&self, source: &str, results: &[HealthResult]) {
        for result in results {
            self.log_health(source, result);
        }
    }

    /// Log an enriched proxy (alive, with geo info).
    pub fn log_enriched(&self, source: &str, ep: &EnrichedProxy) {
        let entry = json!({
            "ts": Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            "event": "enriched",
            "source": source,
            "type": ep.node.proxy_type(),
            "name": ep.node.name(),
            "host": ep.node.host(),
            "port": ep.node.port(),
            "latency_ms": ep.latency_ms,
            "alive": true,
            "country_code": ep.country_code,
            "emoji": ep.emoji,
        });
        self.write_entry(&entry.to_string());
    }

    /// Log a batch of enriched proxies.
    pub fn log_enriched_batch(&self, source: &str, proxies: &[EnrichedProxy]) {
        for ep in proxies {
            self.log_enriched(source, ep);
        }
    }

    fn write_entry(&self, line: &str) {
        if let Ok(mut guard) = self.file.lock()
            && let Some(ref mut file) = *guard {
                let _ = writeln!(file, "{}", line);
            }
    }
}

fn open_log_file(path: &PathBuf) -> Option<std::fs::File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
            && let Err(e) = fs::create_dir_all(parent) {
                log::warn!(
                    "Failed to create proxy log directory '{}': {}",
                    parent.display(),
                    e
                );
                return None;
            }
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => Some(file),
        Err(e) => {
            log::warn!(
                "Failed to open proxy log file '{}': {}",
                path.display(),
                e
            );
            None
        }
    }
}
