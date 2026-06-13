# Overview

This page provides a comprehensive overview of the Surfboard profile format. Surfboard's configuration system is designed for flexibility and power, allowing users to define sophisticated proxy rules and network behaviors.

Surfboard follows Surge's profile format.

Surge's profile documentation can be viewed at https://manual.nssurge.com/.

The following example demonstrates a complete profile structure, covering the primary sections: `[General]`, `[Host]`, `[Proxy]`, `[Proxy Group]`, `[Rule]`, and `[Panel]`.

```
#!MANAGED-CONFIG http://test.com/surfboard.conf interval=60 strict=true
[General]
dns-server = system, 8.8.8.8, 8.8.4.4, 9.9.9.9:9953
doh-server = https://9.9.9.9/dns-query, https://1.1.1.1/dns-query
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local, www.example.com
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://www.gstatic.cn/generate_204
test-timeout = 5
always-real-ip = *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com
http-listen = 0.0.0.0:1234
socks5-listen = 127.0.0.1:1235
udp-policy-not-supported-behaviour = DIRECT
ipv6 = false

[Host]
abc.com = 1.2.3.4
*.dev = 6.7.8.9
foo.com = bar.com
bar.com = server:8.8.8.8

[Proxy]
On = direct
Off = reject

ProxyHTTP = http, 1.2.3.4, 443, username, password
ProxyHTTPS = https, 1.2.3.4, 443, username, password, skip-cert-verify=true, sni=www.google.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640
ProxySOCKS5 = socks5, 1.2.3.4, 443, username, password, udp-relay=false
ProxySOCKS5TLS = socks5-tls, 1.2.3.4, 443, username, password, skip-cert-verify=true, sni=www.google.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640

ProxySS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=abcd1234, udp-relay=false, obfs=http, obfs-host=www.google.com, obfs-uri=/

ProxyVMess = vmess, 1.2.3.4, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119, udp-relay=false, ws=true, tls=true, ws-path=/v2, ws-headers=X-Header-1:value|X-Header-2:value, skip-cert-verify=true, sni=www.google.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640, vmess-aead=true

ProxyTrojan = trojan, 192.168.20.6, 443, password=password1, udp-relay=false, skip-cert-verify=true, sni=www.google.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640

ProxyAnyTLS = anytls, 1.2.3.4, 443, password, skip-cert-verify=true, sni=abc.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640, reuse=false

ProxyHysteria2 = hysteria2, 1.2.3.4, 443, password=pwd, download-bandwidth=100, port-hopping="1234;5000-6000", port-hopping-interval=30, skip-cert-verify=true, sni=example.com, server-cert-fingerprint-sha256=fac26f65c034829da42d740d23c4a7202475a3834f0ebaecae5f934adbbfd640, udp-relay=true

ProxySnell = snell, 1.2.3.4, 443, psk=yourpsk, version=3, udp-relay=true

ProxyWireguard = wireguard, section-name = HomeServer

[WireGuard HomeServer]
private-key = sDEZLACT3zgNCS0CyClgcBC2eYROqYrwLT4wdtAJj3s=
self-ip = 10.0.2.2
dns-server = 8.8.8.8
mtu = 1280
peer = (public-key = fWO8XS9/nwUQcqnkfBpKeqIqbzclQ6EKP20Pgvzwclg=, allowed-ips = 0.0.0.0/0, endpoint = 192.168.20.6:51820, keepalive = 30)

[Proxy Group]
SelectGroup = select, ProxyHTTP, ProxyHTTPS, DIRECT, REJECT
AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5, hidden=true
ExternalGroup = select, policy-path=https://example.com/nodes.txt, policy-regex-filter=HK-.*
AllProxies = select, include-all-proxies = true
LoadBalanceGroup = load-balance, ProxyHTTP, ProxyHTTPS
FallbackGroup = fallback, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, timeout=5

[Rule]
DOMAIN,www.apple.com,ProxyHTTP
DOMAIN-SUFFIX,apple.com,Proxy,force-remote-dns
DOMAIN-KEYWORD,google,Proxy,enhanced-mode
DOMAIN-WILDCARD,*.google.com,Proxy
IP-CIDR,192.168.0.0/16,DIRECT
AND,((DOMAIN-SUFFIX,google.com),(DEST-PORT,443)),Proxy
GEOIP,US,REJECT
PROCESS-NAME,com.android.vending,Proxy
RULE-SET,https://example.com/ruleset.conf,ProxyVMess
SUBNET,TYPE:WIFI,DIRECT
PROTOCOL,QUIC,REJECT
FINAL,ProxyTrojan

[Panel]
PanelA = title="Status Panel", content="System Online\nAll services operational", style=info
```

> Source: https://getsurfboard.com/docs/profile-format/overview/
