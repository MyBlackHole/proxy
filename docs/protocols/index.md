# Protocol Specifications

> Reference documents for proxy protocols supported in this project.

## Supported Protocols (12)

| Protocol | Spec | Status |
|----------|------|--------|
| VMess | [VMess](./vmess.md) | ✅ |
| VLESS | [VLESS](./vless.md) | ✅ |
| Shadowsocks | [Shadowsocks](./shadowsocks.md) | ✅ |
| SSR | [SSR](./ssr.md) | ✅ |
| Trojan | [Trojan](./trojan.md) | ✅ |
| Snell | [Snell](./snell.md) | ✅ |
| Hysteria | - | Inferred from Mihomo config |
| Hysteria2 | - | Inferred from Mihomo/sing-box config |
| TUIC | [TUIC](./tuic.md) | ✅ |
| HTTP/SOCKS5 | - | Standard protocols |
| AnyTLS | - | |
| WireGuard | - | |

## Additional Specs

| Document | Source | Description |
|----------|--------|-------------|
| [SIP022 AEAD-2022](./sip022-aead-2022.md) | shadowsocks.org | SS 2022 cipher protocol spec |
| AEAD (original) | shadowsocks.org | Original SS AEAD protocol |
| Trojan protocol | trojan-gfw.github.io | Trojan protocol spec |

## External References

- shadowsocks.org - SS protocol family specs
- sing-box.sagernet.org - sing-box implementation reference
- wiki.metacubex.one - Clash.Meta/Mihomo implementation reference
- github.com/IrineSistiana/opensnell - OpenSnell protocol reference
