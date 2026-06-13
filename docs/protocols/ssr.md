# ShadowsocksR (SSR) Protocol Reference

> Source: Mihomo docs (wiki.metacubex.one)

## Overview

SSR is a legacy fork of Shadowsocks with protocol and obfuscation plugins built into the protocol itself.

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "ssr"
    type: ssr
    server: server
    port: 443
    cipher: chacha20-ietf
    password: "password"
    obfs: tls1.2_ticket_auth      # Obfuscation method
    protocol: auth_sha1_v4         # Protocol plugin
    obfs-param: domain.tld         # Obfuscation parameter (optional)
    protocol-param: "#"            # Protocol parameter (optional)
    udp: true
```

## Common Ciphers

`rc4-md5`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `chacha20-ietf`

## Protocols

| Protocol | Description |
|----------|-------------|
| `origin` | Original SS protocol |
| `auth_sha1_v4` | Authentication with SHA1 |
| `auth_aes128_md5` | Authentication with AES-128 + MD5 |
| `auth_aes128_sha1` | Authentication with AES-128 + SHA1 |
| `auth_chain_a` | Chain authentication (not recommended) |
| `auth_chain_b` | Chain authentication (not recommended) |

## Obfuscations

| Obfuscation | Description |
|-------------|-------------|
| `plain` | No obfuscation |
| `http_simple` | Simple HTTP伪装 |
| `http_post` | HTTP POST伪装 |
| `tls1.2_ticket_auth` | TLS 1.2 ticket伪装 |
| `tls1.2_ticket_fastauth` | TLS 1.2 ticket快速认证 |
