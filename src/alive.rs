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

pub async fn latency_test(host: &str, port: u16, timeout_secs: u64) -> Result<(bool, u64)> {
    let addr = format!("{}:{}", host, port);
    let dur = Duration::from_secs(timeout_secs);
    let start = tokio::time::Instant::now();
    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            Ok((true, elapsed))
        }
        Ok(Err(_)) => Ok((false, 0)),
        Err(_) => Ok((false, 0)),
    }
}

pub async fn check_alive(node: &ProxyNode) -> HealthResult {
    let (alive, latency_ms) = latency_test(node.host(), node.port(), 5).await.unwrap_or((false, 0));
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
