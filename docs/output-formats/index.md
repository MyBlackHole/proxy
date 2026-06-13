# Output Format Specifications

> Reference documents for proxy output formats supported by this project.

## Supported Output Formats

| Format | File | Status |
|--------|------|--------|
| Clash/Mihomo YAML | [clash.md](./clash.md) | ✅ |
| Clash/Mihomo General Config | [clash-general.md](./clash-general.md) | ✅ |
| Clash/Mihomo Transport Layer | [clash-transport.md](./clash-transport.md) | ✅ |
| sing-box JSON | [sing-box.md](./sing-box.md) | ✅ |
| X-UI Panel | - | ⏳ Not yet |

## Format Mapping

Each internal proxy node must be convertible to all output formats:

```
ProxyNode
  ├──→ Clash YAML (proxies: [...] in clash.yaml)
  ├──→ sing-box JSON (outbounds: [...] in config.json)
  └──→ X-UI Panel format
```

## Clash Output Structure

The output file (`clash.yaml`) has this structure:

```yaml
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - ... # converted proxy nodes

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - ...

rules:
  - ...
```

## sing-box Output Structure

```json
{
  "log": { "level": "info" },
  "inbounds": [...],
  "outbounds": [
    // converted proxy nodes
    { "type": "selector", "tag": "proxy" },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [...]
  }
}
```
