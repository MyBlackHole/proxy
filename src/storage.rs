use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use crate::config::*;
use crate::error::*;

/// Storage abstraction layer.
///
/// Implement this trait to add new storage backends.
/// The `write` method receives the content string and a target identifier
/// (typically the storage item key from config).
pub trait StorageBackend {
    fn write<'a>(
        &'a self,
        content: &'a str,
        target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>;
}

/// Local filesystem storage.
///
/// Writes output to `{base_dir}/{fileid}`.
/// If `fileid` is not set, the target name is used as filename.
pub struct LocalStorage {
    pub base_dir: PathBuf,
    pub fileid: Option<String>,
}

impl StorageBackend for LocalStorage {
    fn write<'a>(
        &'a self,
        content: &'a str,
        target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            let filename = self.fileid.as_deref().unwrap_or(target);
            let path = self.base_dir.join(filename);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, content)?;
            log::info!("Written {} bytes to {}", content.len(), path.display());
            Ok(())
        })
    }
}

/// Create storage backends from configuration.
///
/// Currently only supports `local` engine.
/// New backends can be added by implementing `StorageBackend` and
/// extending this function with a new `StorageConfig` variant.
pub fn create_storage(config: &StorageConfig) -> Result<HashMap<String, Box<dyn StorageBackend>>> {
    match config {
        StorageConfig::Local { items } => {
            let mut map: HashMap<String, Box<dyn StorageBackend>> = HashMap::new();
            for (name, item) in items {
                let base_dir = item.dir.clone().unwrap_or_else(|| ".".to_string());
                map.insert(
                    name.clone(),
                    Box::new(LocalStorage {
                        base_dir: PathBuf::from(base_dir),
                        fileid: item.fileid.clone(),
                    }),
                );
            }
            Ok(map)
        }
    }
}
