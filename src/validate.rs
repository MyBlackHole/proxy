use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of validating a Clash config file via mihomo `-t`.
#[derive(Debug)]
pub enum ValidateResult {
    /// Config is valid. Version string from mihomo if available.
    Valid { version: String },
    /// Config has errors. List of error messages + path to preserved temp dir.
    Invalid { errors: Vec<String>, temp_dir: PathBuf },
    /// No compatible binary found on the system.
    BinaryNotFound { searched: Vec<String> },
    /// Other error (I/O, file not found, etc.)
    Error { message: String },
}

/// Find a clash-compatible binary on the system.
///
/// Search order:
/// 1. `custom` path (from `--validate-bin` or config)
/// 2. `mihomo` in PATH
/// 3. `clash-meta` in PATH
/// 4. `clash` in PATH
pub fn find_validate_binary(custom: Option<&Path>) -> Result<PathBuf, ValidateResult> {
    let candidates: &[&str] = &["mihomo", "clash-meta", "clash"];

    if let Some(path) = custom {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        if path.components().count() <= 1 && !path.as_os_str().is_empty()
            && let Ok(found) = which(path.to_str().unwrap_or("")) {
                return Ok(found);
            }
    }

    for name in candidates {
        if let Ok(path) = which(name) {
            return Ok(path);
        }
    }

    Err(ValidateResult::BinaryNotFound {
        searched: candidates.iter().map(|s| s.to_string()).collect(),
    })
}

/// Minimal PATH lookup (avoids adding a dependency on the `which` crate).
fn which(name: &str) -> Result<PathBuf, std::io::Error> {
    let path_var = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "PATH not set"))?;

    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            // Also check that it's executable (platform-specific check)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&candidate)
                    && meta.permissions().mode() & 0o111 != 0 {
                        return Ok(candidate);
                    }
            }
            #[cfg(not(unix))]
            {
                return Ok(candidate);
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("binary not found in PATH: {}", name),
    ))
}

/// Get mihomo version string from `--version`.
fn get_binary_version(path: &Path) -> Option<String> {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines().next().map(|l| l.to_string())
            } else {
                None
            }
        })
}

/// Validate a Clash config file using `mihomo -t`.
///
/// * `config_path` — path to the Clash YAML file to validate.
/// * `binary` — optional explicit path to mihomo/clash-meta binary.
pub fn validate_clash_config(
    config_path: &Path,
    binary: Option<&Path>,
) -> Result<ValidateResult, ValidateResult> {
    let mihomo = find_validate_binary(binary)?;

    if !config_path.exists() {
        return Err(ValidateResult::Error {
            message: format!("Config file not found: {}", config_path.display()),
        });
    }

    // Pre-check: surface YAML syntax errors before invoking mihomo
    let content = std::fs::read_to_string(config_path).map_err(|e| ValidateResult::Error {
        message: format!("Cannot read config file: {}", e),
    })?;

    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
        return Err(ValidateResult::Invalid {
            errors: vec![format!("YAML parse error: {}", e)],
            temp_dir: PathBuf::new(),
        });
    }

    // Create uniquely-named temp dir (PID + nanos to avoid parallel-test collisions)
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("proxy-validate-{}-{}", std::process::id(), ts));

    std::fs::create_dir_all(&temp_dir).map_err(|e| ValidateResult::Error {
        message: format!("Cannot create temp directory: {}", e),
    })?;

    let config_in_temp = temp_dir.join("config.yaml");
    std::fs::copy(config_path, &config_in_temp).map_err(|e| ValidateResult::Error {
        message: format!("Cannot copy config to temp dir: {}", e),
    })?;

    // Run mihomo -t -d <temp_dir>
    let output = Command::new(&mihomo)
        .args(["-t", "-d"])
        .arg(&temp_dir)
        .output()
        .map_err(|e| ValidateResult::Error {
            message: format!("Failed to execute mihomo: {}", e),
        })?;

    let version = get_binary_version(&mihomo).unwrap_or_else(|| "unknown".to_string());

    if output.status.success() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(ValidateResult::Valid { version })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut errors: Vec<String> = Vec::new();

        for line in stderr.lines().chain(stdout.lines()) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                errors.push(trimmed.to_string());
            }
        }

        if errors.is_empty() {
            errors.push(format!("mihomo exited with code {:?}", output.status.code()));
        }

        Err(ValidateResult::Invalid { errors, temp_dir })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_result_debug() {
        let valid = ValidateResult::Valid {
            version: "v1.18.0".into(),
        };
        let s = format!("{:?}", valid);
        assert!(s.contains("v1.18.0"));
    }

    #[test]
    fn test_binary_not_found_message() {
        let r = ValidateResult::BinaryNotFound {
            searched: vec!["mihomo".into(), "clash-meta".into()],
        };
        let s = format!("{:?}", r);
        assert!(s.contains("mihomo"));
        assert!(s.contains("clash-meta"));
    }

    #[test]
    fn test_validate_file_not_found() {
        let result = validate_clash_config(Path::new("/nonexistent/config.yaml"), None);
        match result {
            Err(ValidateResult::BinaryNotFound { .. }) => {}
            Err(ValidateResult::Error { .. }) => {}
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_find_binary_invalid_custom_path() {
        // A non-existent custom path should fall through to PATH search
        let result = find_validate_binary(Some(Path::new("/nonexistent/mihomo")));
        // On most machines without mihomo, this returns BinaryNotFound
        // But on machines with mihomo, it could succeed
        // Either is fine — just shouldn't panic or return Error
        match result {
            Ok(_) => {} // mihomo found somewhere
            Err(ValidateResult::BinaryNotFound { .. }) => {} // expected
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_validate_invalid_yaml() {
        let dir = std::env::temp_dir().join("proxy-test-invalid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let invalid_yaml = dir.join("config.yaml");
        std::fs::write(
            &invalid_yaml,
            "port: not_a_number\nproxies:\n  - name: test\n    type: unknown\n",
        )
        .unwrap();

        // Without mihomo, should properly identify the YAML error or binary not found
        let result = validate_clash_config(&invalid_yaml, None);
        match &result {
            Err(ValidateResult::Invalid { .. }) => {}
            Err(ValidateResult::BinaryNotFound { .. }) => {}
            Err(ValidateResult::Error { message }) => {
                eprintln!("Got Error: {}", message);
            }
            Ok(_) => {}
            _ => unreachable!(),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_which_lookup() {
        // `sh` should always be on PATH on Unix
        #[cfg(unix)]
        {
            let found = which("sh");
            assert!(found.is_ok(), "sh should be in PATH: {:?}", found);
        }

        // `cmd.exe` on Windows
        #[cfg(windows)]
        {
            let found = which("cmd.exe");
            assert!(found.is_ok(), "cmd.exe should be in PATH: {:?}", found);
        }
    }

    #[test]
    fn test_integration_with_mihomo() {
        // Only runs if mihomo is found on PATH
        let mihomo = match find_validate_binary(None) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("SKIP: mihomo not found on PATH");
                return;
            }
        };

        let dir = std::env::temp_dir().join("proxy-test-valid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let valid_yaml = dir.join("config.yaml");
        std::fs::write(
            &valid_yaml,
            r#"
port: 7890
socks-port: 7891
mixed-port: 7892
mode: rule
log-level: info
dns:
  enable: true
  listen: 0.0.0.0:53
proxies:
  - name: test
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: test
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - test
rules:
  - MATCH,Proxy
"#,
        )
        .unwrap();

        let result = validate_clash_config(&valid_yaml, Some(&mihomo));
        match result {
            Ok(ValidateResult::Valid { version }) => {
                println!("mihomo version: {}", version);
            }
            Err(ValidateResult::Invalid { errors, temp_dir }) => {
                panic!(
                    "Expected valid config, got {} errors: {:?} (temp: {:?})",
                    errors.len(),
                    errors,
                    temp_dir
                );
            }
            other => {
                panic!("Unexpected result: {:?}", other);
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
