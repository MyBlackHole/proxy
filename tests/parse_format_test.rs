#[test]
fn test_parse_clash_yaml() {
    let content = r#"mixed-port: 7890
proxies:
  - {name: "UK 1", server: 151.101.74.119, port: 443, type: vless, uuid: "96eec36e-2c44-5b09-898e-6f0f0526e57f", network: h2, tls: true}
  - name: "US 1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "test123"
"#;
    let fmt = proxy_collector::subscribe::detect_format(content.as_bytes());
    assert_eq!(fmt, proxy_collector::subscribe::SubscriptionFormat::YAML);
    let links = proxy_collector::subscribe::extract_links(content, fmt);
    assert!(links.iter().any(|l| l.starts_with("vless://")));
    assert!(links.iter().any(|l| l.starts_with("ss://")));
    println!("Clash YAML: {} links ✓", links.len());
}

#[test]
fn test_parse_surfboard() {
    let content = r#"[Proxy]
US 1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=test123"#;
    let fmt = proxy_collector::subscribe::detect_format(content.as_bytes());
    assert_eq!(fmt, proxy_collector::subscribe::SubscriptionFormat::Surfboard);
    let links = proxy_collector::subscribe::extract_links(content, fmt);
    assert!(!links.is_empty());
    assert!(links[0].starts_with("ss://"));
    println!("Surfboard: {} links ✓", links.len());
}

#[test]
fn test_parse_quantumult_x() {
    let content = r#"shadowsocks=1.2.3.4:8388, method=aes-256-gcm, password=test123, tag=US 1"#;
    let fmt = proxy_collector::subscribe::detect_format(content.as_bytes());
    assert_eq!(fmt, proxy_collector::subscribe::SubscriptionFormat::QuantumultX);
    let links = proxy_collector::subscribe::extract_links(content, fmt);
    assert!(!links.is_empty());
    println!("Quantumult X: {} links ✓", links.len());
}

#[test]
fn test_parse_singbox() {
    let content = r#"[
  {"type": "shadowsocks", "tag": "US 1", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "test123"}
]"#;
    let fmt = proxy_collector::subscribe::detect_format(content.as_bytes());
    assert_eq!(fmt, proxy_collector::subscribe::SubscriptionFormat::SingBox);
    let links = proxy_collector::subscribe::extract_links(content, fmt);
    assert!(!links.is_empty());
    assert!(links[0].starts_with("ss://"));
    println!("Sing-box: {} links ✓", links.len());
}
