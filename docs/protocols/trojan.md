# Trojan Protocol Reference

> Sources: sing-box docs, Mihomo docs

## Overview

Trojan uses TLS to wrap proxy traffic. It uses a password for authentication and can optionally use Shadowsocks AEAD for additional encryption (trojan-go).

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    udp: true
    sni: example.com
    alpn: [h2, http/1.1]
    client-fingerprint: random
    skip-cert-verify: true
    ss-opts:                      # trojan-go AEAD encryption
      enabled: false
      method: aes-128-gcm         # aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
      password: "example"
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    network: tcp                   # tcp / ws / grpc
    smux:
      enabled: false
```

## sing-box Outbound Format

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "network": "tcp",
  "tls": {},
  "multiplex": {},
  "transport": {}
}
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `password` | Yes | Trojan password |
| `tls` | No | TLS configuration |
| `transport` | No | V2Ray transport (ws/grpc) |
| `ss-opts` | No | trojan-go AEAD encryption layer |
| `network` | No | `tcp` (default) or `udp` |
