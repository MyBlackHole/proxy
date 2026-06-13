//! 管道集成测试：验证 fetch → extract → validate 三阶段数据流正确。
//!
//! 由于 validator 需要真实网络连接来验证代理存活，我们通过 persistence
//! 输出文件来验证 extractor 阶段是否正确提取了代理链接。

use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 启动一个最小 HTTP 服务器，返回指定的 content，用于管道测试。
///
/// 返回 (url, shutdown_signal)，shutdown_signal 置 true 时服务器关闭。
async fn serve_content(
    content: &'static str,
    content_type: &'static str,
) -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            }
            let (mut stream, _) = match tokio::time::timeout(
                Duration::from_millis(100),
                listener.accept(),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => continue,
            };

            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
                content.len(),
                content_type,
                content,
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    (format!("http://{}", addr), shutdown)
}

#[tokio::test]
async fn test_pipeline_extracts_proxy_links_from_plaintext_subscription() {
    // ── 准备：启动一个返回纯文本代理链接的 HTTP 服务器 ──
    // 使用 RFC 5737 保留地址段（TEST-NET），保证不可达，避免 TCP 验证意外通过
    let proxy_content = "\
vmess://eyJhZGQiOiIxOTIuMC4yLjEiLCJwb3J0Ijo0NDN9
trojan://password@192.0.2.2:443
ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTkyLjAuMi4zOjgzODg=
";
    let (url, shutdown) = serve_content(proxy_content, "text/plain").await;

    // ── 执行 ──
    let dir = tempfile::tempdir().unwrap();
    let config = proxy_collector::crawl::PipelineConfig {
        fetch_concurrency: 2,
        validate_concurrency: 2,
        validate_batch_size: 50,
        nested_max_rounds: 0,
        persist_dir: dir.path().to_path_buf(),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = proxy_collector::crawl::run_pipeline(&client, &config, &[url.clone()]).await;

    // ── 验证 ──

    // 1. Persistence: extractor 应写入了 proxies.txt
    let extractor_file = dir.path().join("extractor").join("proxies.txt");
    assert!(
        extractor_file.exists(),
        "extractor 应输出 proxies.txt: {:?}",
        extractor_file
    );

    let extracted: Vec<String> = BufReader::new(
        std::fs::File::open(&extractor_file).unwrap(),
    )
    .lines()
    .map_while(Result::ok)
    .collect();

    assert!(
        extracted.iter().any(|l| l.starts_with("vmess://")),
        "应提取 vmess 链接，实际: {:?}",
        extracted
    );
    assert!(
        extracted.iter().any(|l| l.starts_with("trojan://")),
        "应提取 trojan 链接，实际: {:?}",
        extracted
    );
    assert!(
        extracted.iter().any(|l| l.starts_with("ss://")),
        "应提取 ss 链接，实际: {:?}",
        extracted
    );

    // 2. 管道应正常完成（不 hang）
    // pipeline 内部 validator 会尝试连接这些代理（都是假的）
    // 结果应该为空（验证全部失败）
    assert!(
        result.is_empty(),
        "所有代理都是伪造的，应无验证通过的代理"
    );

    // ── 清理 ──
    shutdown.store(true, Ordering::SeqCst);
}

#[tokio::test]
async fn test_pipeline_stream_extracts_proxy_links() {
    // ── 准备 ──
    let proxy_content = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ==";
    let (url, shutdown) = serve_content(proxy_content, "text/plain").await;

    let dir = tempfile::tempdir().unwrap();
    let config = proxy_collector::crawl::PipelineConfig {
        fetch_concurrency: 2,
        validate_concurrency: 2,
        validate_batch_size: 50,
        nested_max_rounds: 0,
        persist_dir: dir.path().to_path_buf(),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // ── streaming 模式 ──
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let pipeline_handle = tokio::spawn(async move {
        proxy_collector::crawl::run_pipeline_stream(&client, &config, rx).await
    });

    tx.send(url).unwrap();
    drop(tx); // 信号流结束

    let result = pipeline_handle.await.unwrap();

    // ── 验证 ──
    let extractor_file = dir.path().join("extractor").join("proxies.txt");
    assert!(
        extractor_file.exists(),
        "extractor 应输出 proxies.txt"
    );

    let extracted: Vec<String> = BufReader::new(
        std::fs::File::open(&extractor_file).unwrap(),
    )
    .lines()
    .map_while(Result::ok)
    .collect();

    assert!(
        extracted.iter().any(|l| l.starts_with("vmess://")),
        "应提取 vmess 链接"
    );
    assert!(
        result.is_empty(),
        "伪造的代理应验证失败"
    );

    shutdown.store(true, Ordering::SeqCst);
}
