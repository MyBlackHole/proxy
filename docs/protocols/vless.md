# VLESS Protocol Reference

> Sources: sing-box docs, Mihomo docs

## Overview

VLESS is a lightweight version of VMess with reduced protocol overhead. Supports XTLS Vision flow control and multiple transport protocols.

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "vless"
    type: vless
    server: server
    port: 443
    udp: true
    uuid: uuid
    flow: xtls-rprx-vision
    packet-encoding: xudp         # "" / packetaddr / xudp
    encryption: ""                # Mihomo-specific encryption config
    tls: true
    servername: example.com
    alpn: [h2, http/1.1]
    fingerprint: xxxx
    client-fingerprint: chrome
    skip-cert-verify: true
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    network: tcp                  # tcp / ws / http / h2 / grpc / xhttp
    smux:
      enabled: false
```

## sing-box Outbound Format

```json
{
  "type": "vless",
  "tag": "vless-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "flow": "xtls-rprx-vision",
  "network": "tcp",
  "tls": {},
  "packet_encoding": "",
  "multiplex": {},
  "transport": {}
}
```

## Flow Control

| Flow | Description |
|------|-------------|
| `xtls-rprx-vision` | XTLS Vision flow (recommended) |

## Transport Options

| Transport | Notes |
|-----------|-------|
| TCP (default) | Raw TCP |
| WS | WebSocket |
| HTTP | HTTP |
| H2 | HTTP/2 |
| gRPC | gRPC |
| XHTTP | Mihomo-specific, HTTP-based multiplex |
