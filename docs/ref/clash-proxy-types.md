# Clash/Mihomo Proxy Type Specifications

Source: https://wiki.metacubex.one/en/config/proxies/

## Shadowsocks (ss)

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
    plugin: obfs
    plugin-opts:
      mode: tls
    smux:
      enabled: false
```

**Ciphers**: aes-128-ctr, aes-192-ctr, aes-256-ctr, aes-128-cfb, aes-192-cfb, aes-256-cfb, aes-128-gcm, aes-192-gcm, aes-256-gcm, aes-128-ccm, aes-192-ccm, aes-256-ccm, aes-128-gcm-siv, aes-256-gcm-siv, chacha20-ietf, chacha20, xchacha20, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, chacha8-ietf-poly1305, xchacha8-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305, lea-128-gcm, lea-192-gcm, lea-256-gcm, rabbit128-poly1305, aegis-128l, aegis-256, aez-384, deoxys-ii-256-128, rc4-md5, none

**Plugins**: obfs, v2ray-plugin, gost-plugin, shadow-tls, restls, kcptun

## ShadowsocksR (ssr)

```yaml
proxies:
  - name: "ssr"
    type: ssr
    server: server
    port: 443
    cipher: chacha20-ietf
    password: "password"
    obfs: tls1.2_ticket_auth
    protocol: auth_sha1_v4
    # obfs-param: domain.tld
    # protocol-param: "#"
    # udp: true
```

## Snell

```yaml
proxies:
  - name: "snell"
    type: snell
    server: server
    port: 44046
    psk: yourpsk
    # version: 4
    # udp: true
    # reuse: false
    # obfs-opts:
    #   mode: http
    #   host: bing.com
```

## VMess

```yaml
proxies:
  - name: "vmess"
    type: vmess
    server: server
    port: 443
    udp: true
    uuid: uuid
    alterId: 0
    cipher: auto              # auto/none/zero/aes-128-gcm/chacha20-poly1305
    packet-encoding: packetaddr  # (empty)/packetaddr/xudp
    global-padding: false
    authenticated-length: false
    tls: true
    servername: example.com
    alpn: [h2, http/1.1]
    fingerprint: xxxx
    client-fingerprint: chrome
    skip-cert-verify: true
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    network: tcp               # ws/http/h2/grpc
```

## VLESS

```yaml
proxies:
  - name: "vless"
    type: vless
    server: server
    port: 443
    udp: true
    uuid: uuid
    flow: xtls-rprx-vision
    packet-encoding: xudp
    tls: true
    servername: example.com
    alpn: [h2, http/1.1]
    fingerprint: xxxx
    client-fingerprint: chrome
    skip-cert-verify: true
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    encryption: ""
    network: tcp               # ws/http/h2/grpc/xhttp
```

## Trojan

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
    fingerprint: xxxx
    skip-cert-verify: true
    ss-opts:
      enabled: false
      method: aes-128-gcm
      password: "example"
    reality-opts:
      public-key: xxxx
      short-id: xxxx
    network: tcp               # ws/grpc
```

## Hysteria (v1)

```yaml
proxies:
  - name: "hysteria"
    type: hysteria
    server: server.com
    port: 443
    # ports: 1000,2000-3000,4000
    auth-str: yourpassword
    # obfs: obfs_str
    # alpn: [h3]
    protocol: udp              # udp/wechat-video/faketcp
    up: "30 Mbps"
    down: "200 Mbps"
    # sni: server.com
    # skip-cert-verify: false
    # recv-window-conn: 12582912
    # recv-window: 52428800
    # disable_mtu_discovery: false
    # fingerprint: xxxx
    # fast-open: true
```

## Hysteria2

```yaml
proxies:
  - name: "hysteria2"
    type: hysteria2
    server: server.com
    port: 443
    ports: 443-8443
    hop-interval: 30
    password: yourpassword
    up: "30 Mbps"
    down: "200 Mbps"
    obfs: salamander
    obfs-password: yourpassword
    sni: server.com
    skip-cert-verify: false
    fingerprint: xxxx
    alpn: [h3]
```

## TUIC

```yaml
proxies:
  - name: tuic
    server: www.example.com
    port: 10443
    type: tuic
    token: TOKEN                 # V4 only
    uuid: 00000000-0000-0000-0000-000000000001  # V5 only
    password: PASSWORD_1          # V5 only
    disable-sni: true
    reduce-rtt: true
    request-timeout: 8000
    udp-relay-mode: native        # native/quic
    # congestion-controller: bbr   # cubic/new_reno/bbr
    # max-udp-relay-packet-size: 1500
    # fast-open: true
    # skip-cert-verify: true
    # max-open-streams: 20
    # sni: example.com
```

## WireGuard

```yaml
# Simplified (single peer)
proxies:
  - name: "wg"
    type: wireguard
    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    server: 162.159.192.1
    port: 2480
    ip: 172.16.0.2
    ipv6: fd01:5ca1:ab1e:80fa:ab85:6eea:213f:f4a5
    public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
    allowed-ips: ['0.0.0.0/0']
    # pre-shared-key: ...
    # reserved: [209,98,59]
    # persistent-keepalive: 0
    udp: true
    # mtu: 1408
    # dialer-proxy: "ss1"
    # remote-dns-resolve: true
    # dns: [1.1.1.1, 8.8.8.8]
```

## HTTP

```yaml
proxies:
  - name: "http"
    type: http
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true
    # skip-cert-verify: true
    # sni: custom.com
    # fingerprint: xxxx
    # ip-version: dual
```

## SOCKS5

```yaml
proxies:
  - name: "socks"
    type: socks5
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true
    # skip-cert-verify: true
    # udp: true
```

## AnyTLS

```yaml
proxies:
  - name: anytls
    type: anytls
    server: 1.2.3.4
    port: 443
    password: "<your password>"
    # client-fingerprint: chrome
    # udp: true
    # idle-session-check-interval: 30
    # idle-session-timeout: 30
    # min-idle-session: 0
    # sni: example.com
    # alpn: [h2, http/1.1]
    # skip-cert-verify: true
```
