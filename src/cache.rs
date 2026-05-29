use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::SystemTime;
use std::fs;

/// Cache entry kind, each with its own default TTL
#[derive(Debug, Clone, Copy)]
pub enum CacheKind {
    Subscription,
    Ruleset,
}

/// Global cache manager initialized once from config
static CACHE: std::sync::LazyLock<std::sync::Mutex<Option<InnerCache>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

struct InnerCache {
    dir: PathBuf,
    subscription_ttl: u64,
    ruleset_ttl: u64,
    serve_stale: bool,
}

/// Initialize the cache system. Must be called once at startup.
pub fn init_cache(
    enabled: bool,
    dir: &str,
    subscription_ttl: u64,
    ruleset_ttl: u64,
    serve_stale: bool,
) {
    if !enabled {
        log::info!("Cache disabled");
        return;
    }

    // Allow TTL=0 (expire immediately). Config layer should set defaults.

    let cache_dir = PathBuf::from(dir);
    if let Err(e) = fs::create_dir_all(&cache_dir) {
        log::warn!("Failed to create cache dir '{}': {}", dir, e);
        return;
    }

    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some(InnerCache {
            dir: cache_dir,
            subscription_ttl,
            ruleset_ttl,
            serve_stale,
        });
        log::info!(
            "Cache initialized: dir={}, sub_ttl={}s, ruleset_ttl={}s, serve_stale={}",
            dir, subscription_ttl, ruleset_ttl, serve_stale,
        );
    }
}

/// Read cache for the given key and kind. Returns cached content if valid (within TTL).
pub fn get(kind: CacheKind, url: &str) -> Option<String> {
    let cache = CACHE.lock().unwrap_or_else(|e| {
        log::error!("Cache mutex poisoned: {}", e);
        e.into_inner()
    });
    let inner = cache.as_ref()?;
    let ttl = match kind {
        CacheKind::Subscription => inner.subscription_ttl,
        CacheKind::Ruleset => inner.ruleset_ttl,
    };
    let path = cache_path(&inner.dir, url);

    let metadata = fs::metadata(&path).ok()?;

    // Check TTL
    let modified = metadata.modified().ok()?;
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        .as_secs();

    if age >= ttl {
        // Expired — return None but keep file for stale serve
        return None;
    }

    match fs::read_to_string(&path) {
        Ok(data) => {
            log::debug!("Cache HIT for {}", url);
            Some(data)
        }
        Err(_) => None,
    }
}

/// Read stale cache for the given key (ignores TTL). Used for fallback on fetch failure.
/// Returns None if serve_stale is disabled in config.
pub fn get_stale(kind: CacheKind, url: &str) -> Option<String> {
    let cache = CACHE.lock().unwrap_or_else(|e| {
        log::error!("Cache mutex poisoned: {}", e);
        e.into_inner()
    });
    let inner = cache.as_ref()?;
    if !inner.serve_stale {
        return None;
    }
    let path = cache_path(&inner.dir, url);

    match fs::read_to_string(&path) {
        Ok(data) => {
            // Log a warning so user knows they got stale data
            let metadata = fs::metadata(&path).ok();
            let age = metadata
                .and_then(|m| m.modified().ok())
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            log::warn!(
                "Cache STALE serve for {} (age={}s, max_ttl={}s)",
                url, age,
                match kind {
                    CacheKind::Subscription => inner.subscription_ttl,
                    CacheKind::Ruleset => inner.ruleset_ttl,
                },
            );
            Some(data)
        }
        Err(_) => None,
    }
}

/// Write data to cache
pub fn set(_kind: CacheKind, url: &str, data: &str) {
    let cache = CACHE.lock().unwrap_or_else(|e| {
        log::error!("Cache mutex poisoned: {}", e);
        e.into_inner()
    });
    let inner = match cache.as_ref() {
        Some(c) => c,
        None => return,
    };
    let path = cache_path(&inner.dir, url);

    // Ensure parent dir exists
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    match fs::write(&path, data) {
        Ok(_) => log::debug!("Cache SET for {}", url),
        Err(e) => log::warn!("Cache write failed for {}: {}", url, e),
    }
}

pub fn is_enabled() -> bool {
    CACHE.lock().unwrap_or_else(|e| {
        log::error!("Cache mutex poisoned: {}", e);
        e.into_inner()
    }).is_some()
}

/// Build cache file path: cache_dir / Sha256(url)
fn cache_path(dir: &std::path::Path, url: &str) -> PathBuf {
    let hash = hex::encode(Sha256::digest(url.as_bytes()));
    dir.join(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};

    /// Serializes cache tests to prevent global `CACHE` interference in parallel runs.
    static CACHE_TEST_SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn setup() {
        let dir = std::env::temp_dir().join(format!("cache_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_cache(true, dir.to_str().unwrap(), 3600, 86400, true);
    }

    fn teardown() {
        if let Ok(mut cache) = CACHE.lock() {
            if let Some(ref inner) = *cache {
                let _ = fs::remove_dir_all(&inner.dir);
            }
            *cache = None;
        }
    }

    #[test]
    fn test_cache_set_get() {
        let _guard = CACHE_TEST_SERIAL.lock().unwrap();
        setup();
        set(CacheKind::Subscription, "https://example.com/sub", "test-data");
        let result = get(CacheKind::Subscription, "https://example.com/sub");
        assert_eq!(result, Some("test-data".to_string()));
        teardown();
    }

    #[test]
    fn test_cache_miss() {
        let _guard = CACHE_TEST_SERIAL.lock().unwrap();
        setup();
        let result = get(CacheKind::Subscription, "https://nonexistent.example");
        assert_eq!(result, None);
        teardown();
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let _guard = CACHE_TEST_SERIAL.lock().unwrap();
        // Use 0 TTL so entry expires immediately
        let dir = std::env::temp_dir().join(format!("cache_ttl_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_cache(true, dir.to_str().unwrap(), 0, 86400, false);

        set(CacheKind::Subscription, "https://example.com/ttl-test", "data");
        let result = get(CacheKind::Subscription, "https://example.com/ttl-test");
        assert_eq!(result, None, "cache with 0 TTL should expire immediately");

        if let Ok(mut cache) = CACHE.lock() {
            if let Some(ref inner) = *cache {
                let _ = fs::remove_dir_all(&inner.dir);
            }
            *cache = None;
        }
    }

    #[test]
    fn test_stale_serve() {
        let _guard = CACHE_TEST_SERIAL.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("cache_stale_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // 0 TTL so entry expires immediately, but serve_stale=true
        init_cache(true, dir.to_str().unwrap(), 0, 86400, true);

        set(CacheKind::Subscription, "https://example.com/stale-test", "stale-data");
        // get() should return None (expired)
        assert_eq!(get(CacheKind::Subscription, "https://example.com/stale-test"), None);
        // get_stale() should still return data (ignores TTL)
        let stale = get_stale(CacheKind::Subscription, "https://example.com/stale-test");
        assert_eq!(stale, Some("stale-data".to_string()));

        if let Ok(mut cache) = CACHE.lock() {
            if let Some(ref inner) = *cache {
                let _ = fs::remove_dir_all(&inner.dir);
            }
            *cache = None;
        }
    }
}
