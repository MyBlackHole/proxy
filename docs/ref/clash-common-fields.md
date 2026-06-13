# Clash/Mihomo Proxy Common Fields

Source: https://wiki.metacubex.one/en/config/proxies/

## Common Fields (all proxy types)

```yaml
proxies:
  - name: "ss"
    type: ss
    server: server
    port: 443
    ip-version: ipv4        # dual/ipv4/ipv6/ipv4-prefer/ipv6-prefer
    udp: true
    interface-name: eth0
    routing-mark: 1234
    tfo: false
    mptcp: false
    dialer-proxy: ss1
    smux:
      enabled: true
      protocol: smux        # smux/yamux/h2mux
      max-connections: 4
      min-streams: 4
      max-streams: 0
      statistic: false
      only-tcp: false
      padding: true
      brutal-opts:
        enabled: true
        up: 50
        down: 100
```

## Supported Proxy Types

| Type | Description |
|------|-------------|
| `ss` | Shadowsocks |
| `ssr` | ShadowsocksR |
| `vmess` | VMess |
| `vless` | VLESS |
| `trojan` | Trojan |
| `snell` | Snell |
| `http` | HTTP |
| `socks` | SOCKS5 |
| `hysteria` | Hysteria |
| `hysteria2` | Hysteria2 |
| `tuic` | TUIC |
| `wireguard` | WireGuard |
| `anytls` | AnyTLS |
| `tailscale` | Tailscale |
| `ssh` | SSH |
| `mieru` | Mieru |
| `sudoku` | Sudoku |
| `masque` | MASQUE |
| `trusttunnel` | TrustTunnel |
| `openvpn` | OpenVPN |
| `direct` | DIRECT (built-in) |
| `dns` | DNS (built-in) |
