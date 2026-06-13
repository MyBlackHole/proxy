# proxy-collector 系统架构

```mermaid
---
title: proxy-collector 系统架构
---
graph TB
    subgraph CLI["CLI 入口"]
        direction LR
        CRAWL["proxy-collector crawl"]
        CONVERT["proxy-collector convert"]
    end

    subgraph CRAWL_FLOW["Crawl 模式 — 采集 → 管道 → 持久化"]
        direction TB
        
        SOURCES["多源爬取<br/>Telegram / GitHub / Google<br/>Yandex / Twitter / Reddit<br/>RSS / Proxy Sites"]
        AIRPORT["机场订阅自动注册<br/>airport.rs"]
        URL_COLLECT["dedup 去重<br/>collected_urls.txt"]

        subgraph PIPELINE["流式管道 (pipeline.rs)"]
            direction LR
            
            subgraph FETCHER["Fetcher 阶段"]
                F1["depth::classify<br/>URL 分类"]
                F2["src.resolve()<br/>HTTP 获取"]
                F3["save_fetched<br/>→ meta.json + content.txt"]
            end

            subgraph EXTRACTOR["Extractor 阶段"]
                E1["extract_terminal<br/>提取代理链接"]
                E2["parser::parse_proxy_url<br/>识别协议 / 解码"]
                E3["save_extracted<br/>→ {url, proxies}.json"]
                E4["extract_sub_sources<br/>cascade 嵌套 URL"]
                E5["seen_sub_sources<br/>HashSet 去重"]
            end

            subgraph VALIDATOR["Validator 阶段"]
                V1["batch 积累"]
                V2["alive::check_alive_batch<br/>TCP 并发测活 + 延迟"]
                V3["save_validated<br/>→ proxies.jsonl"]
            end

            subgraph CHANNELS["Channel 数据流"]
                CT["CrawlTask{url, remaining}"]
                CTX["ContentTask{url, content, remaining}"]
                PT["ProxyNode (12 种协议)"]
            end

            subgraph WATCHDOG["Shutdown Watcher"]
                WC["work_counter (AtomicIsize)<br/>=0 时触发 shutdown"]
            end

            CT --> FETCHER
            FETCHER --> CTX --> EXTRACTOR
            EXTRACTOR --> PT --> VALIDATOR
            
            EXTRACTOR -- "cascade 子 URL" --> CT
            WC -. "监控 counter" .-> ALL_STAGES["三阶段广播 shutdown"]
        end

        POST_PIPELINE["dedup + name conflict 解析<br/>deduce.rs"]
        FINAL_YAML["proxies.yaml<br/>全量快照"]
    end

    subgraph CONVERT_FLOW["Convert 模式 — 加载 → 预处理 → 输出"]
        LOAD["load_final_proxies<br/>proxies.yaml"]
        
        subgraph PREPROCESS["预处理 (preprocess.rs)"]
            P1["include / exclude 过滤"]
            P2["sort_by_latency / name"]
            P3["strip_emoji_prefix"]
            P4["regex_rename"]
            P5["dedup + 协议版本过滤"]
        end

        subgraph BUILDER["Clash 构建 (builder.rs)"]
            B1["Group 映射<br/>custom_group / direct"]
            B2["Rule Provider 生成<br/>ruleset.rs"]
            B3["Template 渲染<br/>→ clash.yaml"]
        end

        STORAGE["Storage 推送<br/>local / S3 / ..."]
    end

    %% 数据流连接
    CRAWL --> SOURCES
    SOURCES --> AIRPORT --> URL_COLLECT --> PIPELINE
    PIPELINE --> POST_PIPELINE --> FINAL_YAML

    CONVERT --> LOAD --> PREPROCESS --> BUILDER --> STORAGE

    %% 跨模式连接
    FINAL_YAML -. "crawl persist → convert 加载" .-> LOAD

    %% 持久化架构
    subgraph PERSIST["磁盘持久化 (cache.rs — PersistStore)"]
        PD["pipeline_data/"]
        FETCHER_DIR["fetcher/<br/>&lt;sha256(url)&gt;/<br/>├─ meta.json<br/>└─ content.txt"]
        EXTRACTOR_DIR["extractor/<br/>&lt;sha256&gt;.json<br/>{url, proxies}"]
        VALIDATOR_DIR["validator/<br/>proxies.jsonl<br/>32MB 自动旋转"]
    end

    FETCHER --- FETCHER_DIR
    EXTRACTOR --- EXTRACTOR_DIR
    VALIDATOR --- VALIDATOR_DIR
```

## 核心数据路径

| 阶段 | 输入 | 输出 | 持久化 |
|------|------|------|--------|
| **Fetcher** | `CrawlTask{url, remaining}` | `ContentTask{url, content, remaining}` | `<sha256>/meta.json` + `content.txt` |
| **Extractor** | `ContentTask` | `ProxyNode` (12 种协议) | `<sha256>.json` → `{"url","proxies"}` |
| **Validator** | `ProxyNode` | `EnrichedProxy{alive, latency, ...}` | `proxies.jsonl` (32 MiB 旋转) |

## 关键设计点

- **管道是写通（write-through sink）** — 持久化是纯副作用，不阻塞 channel 数据流
- **work_counter 仅 extractor 递减** — fetcher 是中转不参与计数；resolve 失败时 spawned task 即时递减防止泄漏
- **Cascade 去重** — `seen_sub_sources: HashSet<String>` 防止相同子 URL 被重复抓取
- **中间数据自动清理** — 每次 `PersistStore::new()` 清除 `fetcher/` `extractor/`，保留 `proxies.jsonl` 和 `proxies.yaml`
- **双模式分工** — `crawl` 负责采集 + 管道处理 + 持久化；`convert` 负责加载 + 预处理 + Clash 构建 + 存储推送
