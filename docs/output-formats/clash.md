# Clash/Mihomo Proxy Configuration Reference

> Sources: https://wiki.metacubex.one/config/proxies/

## Overview

Proxies are defined as YAML list entries under the `proxies` key. Each proxy has common fields plus protocol-specific fields.

## Common Fields

```yaml
proxies:
  - name: "proxy-name"     # Unique proxy name
    type: ss                # Proxy type
    server: server          # Server address
    port: 443              # Server port
    udp: true              # Enable UDP (default: false)
    smux:
      enabled: false       # Multiplexing
```

## Proxy Types

| Type | Description |
|------|-------------|
| `ss` | Shadowsocks |
| `ssr` | ShadowsocksR |
| `snell` | Snell |
| `vmess` | VMess |
| `vless` | VLESS |
| `trojan` | Trojan |
| `hysteria` | Hysteria v1 |
| `hysteria2` | Hysteria v2 |
| `tuic` | TUIC |
| `http` | HTTP proxy |
| `socks` | SOCKS5 proxy |
| `direct` | Direct connection |
| `wireguard` | WireGuard |
| `anytls` | AnyTLS |
| `tailscale` | Tailscale |
| `ssh` | SSH tunnel |
| `openvpn` | OpenVPN |

## Quick Reference by Protocol

### Shadowsocks (`ss`)
```yaml
type: ss
cipher: aes-128-gcm         # See cipher list
password: "password"
plugin: obfs                # Optional plugins
plugin-opts:
  mode: tls
```

### ShadowsocksR (`ssr`)
```yaml
type: ssr
cipher: chacha20-ietf
password: "password"
obfs: tls1.2_ticket_auth
protocol: auth_sha1_v4
```

### Snell
```yaml
type: snell
psk: yourpsk
version: 4
obfs-opts:
  mode: http
  host: bing.com
```

### VMess
```yaml
type: vmess
uuid: uuid
alterId: 0
cipher: auto
network: tcp                # tcp/ws/http/h2/grpc
```

### VLESS
```yaml
type: vless
uuid: uuid
flow: xtls-rprx-vision
network: tcp                # tcp/ws/http/h2/grpc/xhttp
```

### Trojan
```yaml
type: trojan
password: yourpsk
network: tcp                # tcp/ws/grpc
```

### Hysteria
```yaml
type: hysteria
auth-str: yourpassword       # or auth_str
protocol: udp               # udp/wechat-video/faketcp
up: "30 Mbps"
down: "200 Mbps"
```

### Hysteria2
```yaml
type: hysteria2
password: yourpassword
up: "30 Mbps"
down: "200 Mbps"
obfs: salamander            # Optional
```

### TUIC
```yaml
type: tuic
token: TOKEN                # v4
# OR for v5:
uuid: uuid
password: password
udp-relay-mode: native
congestion-controller: bbr
```
