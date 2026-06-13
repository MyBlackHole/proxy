# Clash/Mihomo Transport Configuration

Source: https://wiki.metacubex.one/en/config/proxies/transport/

## ws-opts (WebSocket transport)

```yaml
proxies:
  - name: "ws-opts-example"
    type: xxxxx
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: example.com
      max-early-data:
      early-data-header-name:
      v2ray-http-upgrade: false
      v2ray-http-upgrade-fast-open: false
```

## http-opts (HTTP transport)

```yaml
proxies:
  - name: "http-opts-example"
    type: xxxxx
    network: http
    http-opts:
      method: "GET"
      path:
        - '/'
        - '/video'
      headers:
        Connection:
          - keep-alive
```

## h2-opts (HTTP/2 transport)

```yaml
proxies:
  - name: "h2-opts-example"
    type: xxxxx
    network: h2
    h2-opts:
      host:
        - example.com
      path: /
```

## grpc-opts (gRPC transport)

```yaml
proxies:
  - name: "grpc-opts-example"
    type: xxxxx
    network: grpc
    grpc-opts:
      grpc-service-name: example
      # grpc-user-agent:
      # ping-interval: 0
      # max-connections: 1
      # min-streams: 0
      # max-streams: 0
```

## xhttp-opts (XHTTP transport - VLESS only)

```yaml
proxies:
  - name: "xhttp-opts-example"
    type: vless
    server: server
    port: 443
    uuid: uuid
    udp: true
    tls: true
    network: xhttp
    alpn: [h2]
    xhttp-opts:
      path: "/"
      host: xxx.com
      # mode: "stream-one"
      # headers:
      #   X-Forwarded-For: ""
      # ... (many more options)
```

## Transport types per protocol

| Protocol | Supported networks |
|----------|-------------------|
| VMess | ws, http, h2, grpc (default: tcp) |
| VLESS | ws, http, h2, grpc, xhttp (default: tcp) |
| Trojan | ws, grpc (default: tcp) |
| Shadowsocks | (no transport options) |
| Others | tcp only (no transport options) |
