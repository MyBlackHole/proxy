use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid proxy URL: {0}")]
    InvalidProxy(String),

    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    #[error("Protocol not supported: {0}")]
    UnsupportedProtocol(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("No proxies available")]
    NoProxies,

    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AppError>;
