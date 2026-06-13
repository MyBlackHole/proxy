# sing-box Outbound Configuration Reference

> Source: https://sing-box.sagernet.org/configuration/outbound/

## Overview

sing-box outbounds are defined in JSON format within the `outbounds` array. Each outbound has a `type` and `tag`.

```json
{
  "outbounds": [
    {
      "type": "",
      "tag": ""
    }
  ]
}
```

## Outbound Types

| Type | Tag | Description |
|------|-----|-------------|
| `direct` | - | Direct outbound (no proxy) |
| `block` | - | Block traffic |
| `socks` | - | SOCKS5 proxy |
| `http` | - | HTTP proxy |
| `shadowsocks` | - | Shadowsocks proxy |
| `vmess` | - | VMess proxy |
| `trojan` | - | Trojan proxy |
| `vless` | - | VLESS proxy |
| `tuic` | - | TUIC proxy |
| `hysteria` | - | Hysteria v1 proxy |
| `hysteria2` | - | Hysteria v2 proxy |
| `wireguard` | - | WireGuard endpoint |
| `shadowtls` | - | ShadowTLS |
| `anytls` | - | AnyTLS |
| `tor` | - | Tor proxy |
| `ssh` | - | SSH tunnel |
| `dns` | - | DNS outbound |
| `selector` | - | Manual select group |
| `urltest` | - | Auto URL test group |
| `naive` | - | NaiveProxy |

## Shadowsocks

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "method": "2022-blake3-aes-128-gcm",
  "password": "8JCsPssfgS8tiRwiMlhARg==",
  "plugin": "",
  "plugin_opts": "",
  "network": "udp",
  "udp_over_tcp": false,
  "multiplex": {}
}
```

## VMess

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

## Trojan

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "password": "password",
  "network": "tcp",
  "tls": {},
  "multiplex": {},
  "transport": {}
}
```

## VLESS

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

## TUIC

```json
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "password": "hello",
  "congestion_control": "cubic",
  "udp_relay_mode": "native",
  "udp_over_stream": false,
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "network": "tcp",
  "tls": {}
}
```

## Hysteria2

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "server_ports": ["2080:3000"],
  "hop_interval": "30s",
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "cry_me_a_r1ver"
  },
  "password": "password",
  "network": "tcp",
  "tls": {}
}
```

## Common Features

### Multiplex
Configured via `multiplex` field on supported outbounds.

### Dial Fields
Available on all outbounds with server address:
```json
{
  "detour": "proxy-out",
  "bind_interface": "eth0",
  "routing_mark": 1234,
  "domain_resolver": "dns-resolver",
  "tcp_fast_open": true,
  "tcp_multi_path": true,
  "udp_fragment": true,
  "connect_timeout": "5s",
  "udp_timeout": "60s"
}
```
