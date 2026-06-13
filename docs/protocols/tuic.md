# TUIC Protocol Reference

> Sources: sing-box docs, Mihomo docs

## Overview

TUIC (Tunnel UDP over Internet with TLS/QUIC) is a proxy protocol based on QUIC. Supports both v4 (token-based) and v5 (uuid+password-based).

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: tuic
    server: www.example.com
    port: 10443
    type: tuic
    # TUIC v4 (mutually exclusive with v5)
    token: TOKEN
    # TUIC v5 (mutually exclusive with v4)
    uuid: 00000000-0000-0000-0000-000000000001
    password: PASSWORD_1
    # Common options
    ip: 127.0.0.1                        # Override DNS result
    heartbeat-interval: 10000            # ms
    alpn: [h3]
    disable-sni: true
    reduce-rtt: true                     # 0-RTT handshake
    request-timeout: 8000                # ms
    udp-relay-mode: native               # native / quic
    congestion-controller: bbr           # cubic / new_reno / bbr
    bbr-profile: ""                      # standard / conservative / aggressive
    max-udp-relay-packet-size: 1500
    fast-open: true
    skip-cert-verify: true
    max-open-streams: 20
    sni: example.com
```

## sing-box Outbound Format

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

## Version Comparison

| Feature | TUIC v4 | TUIC v5 |
|---------|---------|---------|
| Auth | `token` | `uuid` + `password` |
| Protocol | QUIC | QUIC (enhanced) |
