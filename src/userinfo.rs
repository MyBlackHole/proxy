use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;

/// Parsed subscription usage info from `Subscription-UserInfo` HTTP header.
#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: Option<u64>,
}

/// Global per-URL userinfo store. Populated during subscription fetch,
/// read during output generation.
static USER_INFO_MAP: LazyLock<Mutex<HashMap<String, UserInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Parse a `Subscription-UserInfo` header value into a `UserInfo`.
///
/// Format: `upload=0; download=12345; total=98765; expire=1735689600;`
pub fn parse_header(value: &str) -> UserInfo {
    let mut info = UserInfo::default();
    for pair in value.split(';') {
        let pair = pair.trim();
        if let Some((key, val)) = pair.split_once('=') {
            let key = key.trim().to_lowercase();
            let val = val.trim().parse::<u64>().unwrap_or(0);
            match key.as_str() {
                "upload" => info.upload = val,
                "download" => info.download = val,
                "total" => info.total = val,
                "expire" => info.expire = if val == 0 { None } else { Some(val) },
                _ => {}
            }
        }
    }
    info
}

/// Store userinfo for a subscription URL (from HTTP response header).
pub fn capture(url: &str, header_value: &str) {
    let info = parse_header(header_value);
    if let Ok(mut map) = USER_INFO_MAP.lock() {
        map.insert(url.to_string(), info);
    }
    log::info!("UserInfo for {}: {}", url, format_single(&parse_header(header_value)));
}

/// Build a human-readable summary of all stored userinfos.
pub fn format_all() -> String {
    let map = USER_INFO_MAP.lock().unwrap_or_else(|e| {
        log::error!("USER_INFO_MAP mutex poisoned: {}", e);
        e.into_inner()
    });
    if map.is_empty() {
        return String::new();
    }
    let mut lines: Vec<String> = Vec::new();
    for (url, info) in map.iter() {
        let short = if url.len() > 60 {
            format!("...{}", &url[url.len().saturating_sub(57)..])
        } else {
            url.clone()
        };
        lines.push(format!("# {}  {}", short, format_single(info)));
    }
    lines.join("\n")
}

/// Format a single UserInfo for display.
fn format_single(info: &UserInfo) -> String {
    let used = info.upload + info.download;
    let total_str = human_bytes(info.total);
    let used_str = human_bytes(used);
    let remain = info.total.saturating_sub(used);
    let remain_str = human_bytes(remain);
    let expire_str = info
        .expire
        .map(|ts| {
            // Convert unix timestamp to UTC date string
            let secs = ts as i64;
            let days = secs / 86400;
            let rem = secs % 86400;
            let hours = rem / 3600;
            let minutes = (rem % 3600) / 60;
            format!("{}d {:02}:{:02}h", days, hours, minutes)
        })
        .unwrap_or_else(|| "never".to_string());

    format!(
        "used={}/{} ({} left), expire={}",
        used_str, total_str, remain_str, expire_str
    )
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{:.0}{}", size, UNITS[unit_idx])
    } else {
        format!("{:.2}{}", size, UNITS[unit_idx])
    }
}

/// Check if any userinfo data has been captured.
pub fn has_data() -> bool {
    !USER_INFO_MAP.lock().unwrap_or_else(|e| {
        log::error!("USER_INFO_MAP mutex poisoned: {}", e);
        e.into_inner()
    }).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_header() {
        let info = parse_header("upload=0; download=1234567890; total=9876543210; expire=1735689600;");
        assert_eq!(info.upload, 0);
        assert_eq!(info.download, 1234567890);
        assert_eq!(info.total, 9876543210);
        assert_eq!(info.expire, Some(1735689600));
    }

    #[test]
    fn test_parse_no_expire() {
        let info = parse_header("upload=100; download=200; total=1000");
        assert_eq!(info.upload, 100);
        assert_eq!(info.download, 200);
        assert_eq!(info.total, 1000);
        assert_eq!(info.expire, None);
    }

    #[test]
    fn test_parse_empty() {
        let info = parse_header("");
        assert_eq!(info.upload, 0);
        assert_eq!(info.download, 0);
        assert_eq!(info.total, 0);
        assert_eq!(info.expire, None);
    }

    #[test]
    fn test_parse_case_insensitive() {
        let info = parse_header("Upload=100; DOWNLOAD=200; Total=1000");
        assert_eq!(info.upload, 100);
        assert_eq!(info.download, 200);
        assert_eq!(info.total, 1000);
    }

    #[test]
    fn test_human_bytes() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(1023), "1023B");
        assert_eq!(human_bytes(1024), "1.00KB");
        assert_eq!(human_bytes(1048576), "1.00MB");
        assert_eq!(human_bytes(1073741824), "1.00GB");
    }

    #[test]
    fn test_format_single() {
        let info = UserInfo { upload: 0, download: 500, total: 1024, expire: None };
        let s = format_single(&info);
        assert!(s.contains("500B"));
        assert!(s.contains("1.00KB"));
        assert!(s.contains("never"));
    }
}
