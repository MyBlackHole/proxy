# 免费代理池构建工具

Rust — 高性能、低资源、单二进制部署。

## 核心特性

- **多源爬取** — Telegram / GitHub / Google / Yandex / Twitter
- **智能验证** — TCP 并发直连测活 + 延迟检测
- **单一输出** — 统一 Clash 格式，12 种代理协议全覆盖

## 支持协议

VMess | Trojan | Shadowsocks | SSR | Snell | Hysteria2 | VLESS | Hysteria | TUIC | AnyTLS | HTTP | SOCKS5

## 快速开始

```bash
# 编译
cargo build --release

# 运行
./target/release/proxy-collector -s config.toml
```

### 最小配置示例（TOML）

```toml
[[domains]]
name = "example"
domain = "example.com"
push_to = ["free"]

[crawl]
enable = true

[crawl.github]
enable = true
search_repos = ["Pawdroid/Free-servers"]

[crawl.telegram]
enable = true

[crawl.telegram.users]
proxyshareCN = { push_to = ["free"] }

[groups.free]
[groups.free.targets]
clash = "my-output"

[settings]
socks_proxy = "socks5://127.0.0.1:1081"

[storage]
engine = "local"

[storage.items.my-output]
fileid = "clash.yaml"
folderid = "/tmp/output"
```

### 常用命令

```bash
# 运行完整工作流
proxy-collector -s config.toml

# 仅执行健康检查（跳过爬取）
proxy-collector -s config.toml --check

# 指定并发数
proxy-collector -s config.toml -n 128
```

### SOCKS5 代理

部分爬取源（Telegram、Google、Yandex、Twitter）需要代理访问：

```toml
[settings]
socks_proxy = "socks5://127.0.0.1:1081"
```

## 工作流程

```mermaid
graph LR
    A[配置文件] --> B[多源爬取]
    B --> C[代理聚合]
    C --> D[健康检查]
    D --> E[GeoIP 标记]
    E --> F[Clash 转换]
    F --> G[存储]
```

## 免责声明

禁止使用该项目进行任何盈利活动，对一切非法使用所产生的后果，本人概不负责。使用者应遵守当地法律法规，尊重网站服务条款，合理使用网络资源。
