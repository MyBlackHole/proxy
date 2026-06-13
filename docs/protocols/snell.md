# Snell Protocol Reference

> Source: OpenSnell (IrineSistiana/opensnell), Mihomo docs (wiki.metacubex.one)

## Protocol Overview

Snell is a simple proxy protocol developed by Surge. It uses a pre-shared key for encryption and supports optional obfuscation.

## Versions

| Version | UDP Support | Notes |
|---------|-------------|-------|
| v1 | No | Original |
| v2 | No | |
| v3 | Yes | UDP relay added |
| v4 | Yes | Adds `reuse` option |
| v5 | Yes | Latest |

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "snell"
    type: snell
    server: server
    port: 44046
    psk: yourpsk
    version: 4        # default if omitted
    udp: true          # v3+ only
    reuse: false       # v4+ only
    obfs-opts:
      mode: http       # http or tls
      host: bing.com
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `psk` | Yes | Pre-shared key |
| `version` | No | 1/2/3/4/5, default determined by server |
| `udp` | No | v3+ only |
| `reuse` | No | v4+ only, connection reuse |
| `obfs-opts.mode` | No | `http` or `tls` obfuscation |
| `obfs-opts.host` | No | Obfuscation hostname |

## sing-box Outbound Format

```json
{
  "type": "snell",
  "tag": "snell-out",
  "server": "127.0.0.1",
  "server_port": 44046,
  "psk": "yourpsk",
  "version": 4,
  "obfs": {
    "type": "http",
    "host": "bing.com"
  }
}
```
