# Clash/Mihomo Transport Layer Reference

> Source: https://wiki.metacubex.one/config/proxies/transport/

## Overview

Transport layer defines how VMess/VLESS/Trojan proxy traffic is tunneled. Configured via `network` field and corresponding `*-opts`.

## Network Options

| Value | Opts Field | Protocols Supporting |
|-------|------------|---------------------|
| `tcp` (default) | - | VMess, VLESS, Trojan |
| `ws` | `ws-opts` | VMess, VLESS, Trojan |
| `http` | `http-opts` | VMess, VLESS |
| `h2` | `h2-opts` | VMess, VLESS |
| `grpc` | `grpc-opts` | VMess, VLESS, Trojan |
| `xhttp` | `xhttp-opts` | VLESS only |

## ws-opts (WebSocket)

```yaml
ws-opts:
  path: /path
  headers:
    Host: example.com
  max-early-data:               # Early Data size threshold
  early-data-header-name:
  v2ray-http-upgrade: false
  v2ray-http-upgrade-fast-open: false
```

## http-opts

```yaml
http-opts:
  method: "GET"
  path:
    - '/'
    - '/video'
  headers:
    Connection:
      - keep-alive
```

## h2-opts

```yaml
h2-opts:
  host:
    - example.com
  path: /
```

## grpc-opts

```yaml
grpc-opts:
  grpc-service-name: example
  grpc-user-agent:
  ping-interval: 0
  max-connections: 1
  min-streams: 0
  max-streams: 0
```

## xhttp-opts (VLESS only, Mihomo-specific)

```yaml
xhttp-opts:
  path: "/"
  host: xxx.com
  mode: "stream-one"          # auto / stream-one / stream-up / packet-up
  headers:
    X-Forwarded-For: ""
  no-grpc-header: false
  # Padding & obfuscation
  x-padding-bytes: "100-1000"
  x-padding-obfs-mode: false
  x-padding-key: x_padding
  x-padding-header: Referer
  x-padding-placement: queryInHeader  # queryInHeader / cookie / header / query
  x-padding-method: repeat-x          # repeat-x / tokenish
  # Session settings
  session-placement: path     # path / query / cookie / header
  session-key: ""
  seq-placement: path          # path / query / cookie / header
  seq-key: ""
  uplink-data-placement: body  # body / cookie / header
  uplink-data-key: ""
  uplink-chunk-size: 0
  # HTTP settings
  uplink-http-method: POST     # POST / PUT / PATCH / DELETE
  sc-max-each-post-bytes: 1000000
  sc-min-posts-interval-ms: 30
  # Connection reuse (XMUX)
  reuse-settings:
    max-concurrency: "16-32"
    max-connections: "0"
    c-max-reuse-times: "0"
    h-max-request-times: "600-900"
    h-max-reusable-secs: "1800-3000"
    h-keep-alive-period: 0
```
