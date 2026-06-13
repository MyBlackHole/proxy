# Clash/Mihomo General Configuration Reference

> Source: https://wiki.metacubex.one/config/general/

## Top-Level Configuration

```yaml
# LAN
allow-lan: true
bind-address: "*"
lan-allowed-ips:
  - 0.0.0.0/0
  - ::/0
lan-disallowed-ips:
  - 192.168.0.3/32
authentication:
  - "user1:pass1"
skip-auth-prefixes:
  - 127.0.0.1/8
  - ::1/128

# Mode
mode: rule                    # rule / global / direct

# Logging
log-level: info               # silent / error / warning / info / debug

# Network
ipv6: true
keep-alive-interval: 15
keep-alive-idle: 15
disable-keep-alive: false
find-process-mode: strict     # always / strict / off

# API
external-controller: 127.0.0.1:9090
external-controller-cors:
  allow-origins:
    - '*'
  allow-private-network: true
secret: ""

# UI
external-ui: /path/to/ui/folder
external-ui-name: xd
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"

# Cache
profile:
  store-selected: true
  store-fake-ip: true

# Performance
unified-delay: true
tcp-concurrent: true
interface-name: en0
routing-mark: 6666

# TLS (for API HTTPS)
tls:
  certificate: string
  private-key: string

# GEO
geodata-mode: true
geodata-loader: memconservative
geo-auto-update: false
geo-update-interval: 24
geox-url:
  geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"

# Other
global-ua: clash.meta
etag-support: true
```

## Key Sections

| Section | Description |
|---------|-------------|
| `proxies` | Proxy node definitions |
| `proxy-groups` | Proxy group strategies |
| `rules` | Routing rules |
| `proxy-providers` | External proxy providers |
| `rule-providers` | External rule providers |
| `dns` | DNS configuration |
| `tun` | TUN mode |
| `tunnels` | Traffic tunnels |
| `sniff` | Domain sniffing |
| `sub-rule` | Sub-rules |
| `ntp` | NTP configuration |
| `experimental` | Experimental features |
