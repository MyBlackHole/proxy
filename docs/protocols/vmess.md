# VMess Protocol Reference

> Sources: sing-box docs, Mihomo docs

## Overview

VMess is a protocol originally from V2Ray. It uses UUID for user identification and supports multiple encryption methods and transport protocols.

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "vmess"
    type: vmess
    server: server
    port: 443
    udp: true
    uuid: uuid
    alterId: 0                    # 0 = AEAD, !=0 = legacy
    cipher: auto                  # auto / none / zero / aes-128-gcm / chacha20-poly1305
    packet-encoding: packetaddr   # "" / packetaddr / xudp
    global-padding: false
    authenticated-length: false
    tls: true
    servername: example.com
    alpn: [h2, http/1.1]
    fingerprint: xxxx
    client-fingerprint: chrome
    skip-cert-verify: true
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    network: tcp                  # tcp / ws / http / h2 / grpc
    smux:
      enabled: false
```

## sing-box Outbound Format

```json
{
  "type": "vmess",
  "tag": "vmess-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "security": "auto",
  "alter_id": 0,
  "global_padding": false,
  "authenticated_length": true,
  "network": "tcp",
  "tls": {},
  "packet_encoding": "",
  "multiplex": {},
  "transport": {}
}
```

## Cipher Options

| Value | Description |
|-------|-------------|
| `auto` | Auto-negotiate (recommended) |
| `none` | No encryption |
| `zero` | Zero encryption |
| `aes-128-gcm` | AES-128-GCM |
| `chacha20-poly1305` | ChaCha20-Poly1305 |
| `aes-128-ctr` | Legacy, AEAD disabled |

## Transport Options

| Transport | Alias in YAML | Notes |
|-----------|---------------|-------|
| TCP | `tcp` (default) | Raw TCP |
| WebSocket | `ws` | HTTP upgrade |
| HTTP | `http` | HTTP CONNECT |
| HTTP/2 | `h2` | |
| gRPC | `grpc` | |
