use crate::error::*;
use crate::proxy::*;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct HealthResult {
    pub node: ProxyNode,
    pub alive: bool,
    pub latency_ms: u64,
}

pub async fn latency_test(host: &str, port: u16, timeout_secs: u64, proxy_name: &str) -> Result<(bool, u64)> {
    let addr = format!("{}:{}", host, port);
    let dur = Duration::from_secs(timeout_secs);
    let start = tokio::time::Instant::now();
    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            Ok((true, elapsed))
        }
        Ok(Err(e)) => {
            log::debug!("TCP connect to proxy '{}' ({}:{}) failed: {}", proxy_name, host, port, e);
            Ok((false, 0))
        }
        Err(_) => {
            log::debug!("TCP connect to proxy '{}' ({}:{}) timed out after {}s", proxy_name, host, port, timeout_secs);
            Ok((false, 0))
        }
    }
}

pub async fn check_alive(node: &ProxyNode) -> HealthResult {
    // Skip TCP check for UDP-only protocols (e.g. WireGuard).
    if !node.supports_tcp_check() {
        log::info!("Skipping TCP check for {} proxy '{}' (UDP-only)", node.proxy_type(), node.name());
        return HealthResult {
            node: node.clone(),
            alive: true,
            latency_ms: 0,
        };
    }
    log::debug!("Testing proxy '{}' ({} — {}:{})", node.name(), node.proxy_type(), node.host(), node.port());
    let (alive, latency_ms) = latency_test(node.host(), node.port(), 5, node.name()).await.unwrap_or((false, 0));
    if alive {
        log::debug!("Proxy '{}' ({}) alive ({}ms)", node.name(), node.proxy_type(), latency_ms);
    }
    HealthResult {
        node: node.clone(),
        alive,
        latency_ms,
    }
}

pub async fn check_alive_batch(
    nodes: Vec<ProxyNode>,
    concurrency: usize,
) -> Vec<HealthResult> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(nodes.len());

    for node in nodes {
        // acquire_owned only fails if semaphore is closed — we never close it
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        handles.push(tokio::spawn(async move {
            let _guard = permit;
            check_alive(&node).await
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(r) = handle.await {
            results.push(r);
        }
    }
    results
}
