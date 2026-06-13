# server_local(本地节点）

### 本地节点可通过如下方式添加

* 文本编辑模式
* 点击首页下方工具栏中的+进行(UI方式，仅限shadowsocks节点)
* 设置页面->节点->添加(UI方式，仅限shadowsocks节点)
* 设置页面->配置文件->配置片段->选择类型为节点的配置片段(文本格式)

### QX支持的节点类型如下：

* Shadowsocks
* ShadowsocksR
* HTTP(S)
* Socks5
* VMess
* VLess
* Trojan

当前QX的UI界面仅支持添加Shadowsocks协议类型节点的基本选项，高级选项或者其它协议需要通过文本配置的方式添加到[server_local] 部分。

以下是各节点的文本配置格式示例：

### Shadowsocks（ss）及参数使用格式示例：

```
#Optional field tls13 is only for shadowsocks obfs=wss
shadowsocks=example.com:80, method=chacha20, password=pwd, obfs=http, obfs-host=bing.com, obfs-uri=/resource/file, fast-open=false, udp-relay=false, server_check_url=http://www.apple.com/generate_204, tag=ss-01
shadowsocks=example.com:80, method=chacha20, password=pwd, obfs=http, obfs-host=bing.com, obfs-uri=/resource/file, fast-open=false, udp-relay=false, tag=ss-02
shadowsocks=example.com:443, method=chacha20, password=pwd, obfs=tls, obfs-host=bing.com, fast-open=false, udp-relay=false, tag=ss-03
shadowsocks=example.com:443, method=chacha20, password=pwd, ssr-protocol=auth_chain_b, ssr-protocol-param=def, obfs=tls1.2_ticket_fastauth, obfs-host=bing.com, tag=ssr
shadowsocks=example.com:80, method=aes-128-gcm, password=pwd, obfs=ws, fast-open=false, udp-relay=false, tag=ss-ws-01
shadowsocks=example.com:80, method=aes-128-gcm, password=pwd, obfs=ws, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=ss-ws-02
shadowsocks=example.com:443, method=aes-128-gcm, password=pwd, obfs=wss, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=ss-ws-tls-01
shadowsocks=example.com:443, method=aes-128-gcm, password=pwd, obfs=wss, obfs-uri=/ws, tls13=true, fast-open=false, udp-relay=false, tag=ss-ws-tls-02
```

### vmess及参数使用格式示例：

```
# Optional field tls13 is only for vmess obfs=over-tls and obfs=wss
vmess=example.com:80, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, fast-open=false, udp-relay=false, tag=vmess-01
vmess=example.com:80, method=aes-128-gcm, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, fast-open=false, udp-relay=false, tag=vmess-02
vmess=example.com:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=over-tls, fast-open=false, udp-relay=false, tag=vmess-tls-01
vmess=192.168.1.1:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=over-tls, obfs-host=example.com, fast-open=false, udp-relay=false, tag=vmess-tls-02
vmess=192.168.1.1:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=over-tls, obfs-host=example.com, tls13=true, fast-open=false, udp-relay=false, tag=vmess-tls-03
vmess=example.com:80, method=chacha20-poly1305, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=ws, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vmess-ws-01
vmess=192.168.1.1:80, method=chacha20-poly1305, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=ws, obfs-host=example.com, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vmess-ws-02
vmess=example.com:443, method=chacha20-poly1305, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=wss, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vmess-ws-tls-01
vmess=192.168.1.1:443, method=chacha20-poly1305, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=wss, obfs-host=example.com, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vmess-ws-tls-02
vmess=192.168.1.1:443, method=chacha20-poly1305, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=wss, obfs-host=example.com, obfs-uri=/ws, tls13=true, fast-open=false, udp-relay=false, tag=vmess-ws-tls-03
```

### Vless及参数使用格式示例：

```
vless=example.com:80, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, fast-open=false, udp-relay=false, tag=vless-01

vless=example.com:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=over-tls, fast-open=false, udp-relay=false, tag=vless-tls-01

vless=example.com:80, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=http, obfs-host=bing.com, obfs-uri=/resource/file, fast-open=false, udp-relay=false, server_check_url=http://www.apple.com/generate_204, tag=vless-http

vless=example.com:80, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=ws, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vless-ws-01

vless=example.com:443, method=none, password=23ad6b10-8d1a-40f7-8ad0-e3e35cd32291, obfs=wss, obfs-uri=/ws, fast-open=false, udp-relay=false, tag=vless-ws-tls-01
```

### HTTP(S)及参数使用格式示例：

```
# Optional field tls13 is only for http over-tls=true
http=example.com:80,fast-open=false, udp-relay=false, tag=http-01
http=example.com:80, username=name, password=pwd, fast-open=false, udp-relay=false, tag=http-02
http=example.com:443, username=name, password=pwd, over-tls=true, tls-host=example.com, tls-verification=true, fast-open=false, udp-relay=false, tag=http-tls-01
http=example.com:443, username=name, password=pwd, over-tls=true, tls-host=example.com, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=http-tls-02
```

### Trojan及参数使用格式示例：

```
# Optional field tls13 is only for trojan over-tls=true
trojan=example.com:443, password=pwd, over-tls=true, tls-verification=true, fast-open=false, udp-relay=false, tag=trojan-tls-01
trojan=example.com:443, password=pwd, over-tls=true, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=trojan-tls-02
trojan=192.168.1.1:443, password=pwd, over-tls=true, tls-host=example.com, tls-verification=true, fast-open=false, udp-relay=false, tag=trojan-tls-03
trojan=192.168.1.1:443, password=pwd, over-tls=true, tls-host=example.com, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=trojan-tls-04
```

> Source: https://qx.atlucky.me/shi-yong-fang-fa/pei-zhi-wen-jian-xiang-jie/jie-dian/serverlocal-ben-di-jie-dian
