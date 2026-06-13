# Shadowsocks Protocol Reference

> Sources: sing-box docs (sing-box.sagernet.org), Mihomo docs (wiki.metacubex.one), shadowsocks.org

## Supported Ciphers

### AEAD (Recommended)
| Cipher | Key Size |
|--------|----------|
| `aes-128-gcm` | 16 |
| `aes-192-gcm` | 24 |
| `aes-256-gcm` | 32 |
| `chacha20-ietf-poly1305` | 32 |
| `xchacha20-ietf-poly1305` | 32 |

### 2022 AEAD (BLAKE3)
| Cipher | Key Size |
|--------|----------|
| `2022-blake3-aes-128-gcm` | 16 |
| `2022-blake3-aes-256-gcm` | 32 |
| `2022-blake3-chacha20-poly1305` | 32 |

### Legacy (Deprecated)
`aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20`

### Others (Mihomo-specific)
`aes-128-ccm`, `aes-192-ccm`, `aes-256-ccm`, `aes-128-gcm-siv`, `aes-256-gcm-siv`, `chacha20`, `chacha8-ietf-poly1305`, `xchacha8-ietf-poly1305`, `lea-128-gcm`, `lea-192-gcm`, `lea-256-gcm`, `rabbit128-poly1305`, `aegis-128l`, `aegis-256`, `aez-384`, `deoxys-ii-256-128`, `none`

## Clash/Mihomo Proxy Format

```yaml
proxies:
  - name: "ss1"
    type: ss
    server: server
    port: 443
    cipher: aes-128-gcm
    password: "password"
    udp: true
    udp-over-tcp: false
    udp-over-tcp-version: 2
    ip-version: ipv4
    plugin: obfs           # obfs / v2ray-plugin / gost-plugin / shadow-tls / restls / kcptun
    plugin-opts:
      mode: tls
    smux:
      enabled: false
```

## sing-box Outbound Format

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

## Plugin Support

| Plugin | Description |
|--------|-------------|
| `obfs` | Simple obfuscation (tls/http) |
| `v2ray-plugin` | V2Ray WebSocket transport |
| `gost-plugin` | GOST tunnel plugin |
| `shadow-tls` | TLS伪装 |
| `restls` | TLS 1.3 session伪装 |
| `kcptun` | KCP-based transport |
