# VMessAEAD / VLESS 分享链接标准提案

Source: https://github.com/XTLS/Xray-core/issues/91
Authors: @DuckSoft (Qv2ray), @huyz, @RPRX

## 1 原则

* 必须是合法的 URL
* 对机器友好、对人类可读

## 2 约定

* URL 字段对出现顺序不敏感，但同一字段禁止重复出现
* 所有 URL 字段的 Value 都必须使用 `encodeURIComponent` 进行转义处理
* **所有参数名和常数字符串均区分大小写**。

## 3 概览

```
protocol://
	$(uuid)
	@
	remote-host
	:
	remote-port
?
	<protocol-specific fields>
	<transport-specific fields>
	<tls-specific fields>
#$(descriptive-text)
```

特别说明：`$()` 代表此处需要 `encodeURIComponent`。

## 4 详述

### 4.1 基本信息段

#### 4.1.1 协议名称 `protocol`
所使用的协议名称。取值必须为 `vmess` 或 `vless`。
不可省略，不能为空字符串。

#### 4.1.2 `uuid`
UUID。对应配置文件该项出站中 `settings.vnext[0].users[0].id` 的值。
不可省略，不能为空字符串。

#### 4.1.3 `remote-host`
服务器的域名或 IP 地址。
不可省略，不能为空字符串。
IPv6 地址必须括上方括号。
IDN 域名（如"百度.cn"）必须使用 `xn--xxxxxx` 格式。

#### 4.1.4 `remote-port`
服务器的端口号。
**不可省略**，必须取 `[1,65535]` 中的整数。

#### 4.1.5 `descriptive-text`
服务器的描述信息。
可省略，**不推荐为空字符串**。
必须使用 `encodeURIComponent` 转义。

### 4.2 协议相关段

#### 4.2.1 传输方式 `type`
协议的传输方式。对应配置文件出站中 `settings.vnext[0].streamSettings.network` 的值。
当前的取值必须为 `tcp`、`kcp`、`ws`、`http`、`quic` 其中之一，分别对应 TCP、mKCP、WebSocket、HTTP/2、QUIC 传输方式。
修订：取值还可以是 `grpc`，代表 gRPC 传输方式。

#### 4.2.2 (VMess/VLESS) `encryption`
当协议为 VMess 时，对应配置文件出站中 `settings.security`，可选值为 `auto` / `aes-128-gcm` / `chacha20-poly1305` / `none`。
省略时默认为 `auto`，但不可以为空字符串。**除非指定为 `none`，否则建议省略。**
当协议为 VLESS 时，对应配置文件出站中 `settings.encryption`，当前可选值只有 `none`。
省略时默认为 `none`，但不可以为空字符串。

#### 4.2.3 (VMess) `alterId`、`aid` 等
**没有这些字段**。旧的 VMess 因协议设计出现致命问题，不再适合使用或分享。
此分享标准仅针对 VMess AEAD 和 VLESS。

### 4.3 传输层相关段

#### 4.3.1 底层传输安全 `security`
设定底层传输所使用的 TLS 类型。当前可选值有 `none`，`tls` 和 `xtls`。
省略时默认为 `none`，但不可以为空字符串。

#### 4.3.2 (HTTP/2) `path`
HTTP/2 的路径。省略时默认为 `/`，但不可以为空字符串。**不推荐省略。**
必须使用 `encodeURIComponent` 转义。

#### 4.3.3 (HTTP/2) `host`
客户端进行 HTTP/2 通信时所发送的 `Host` 头部。
省略时复用 `remote-host`，但不可以为空字符串。
若有多个域名，可使用英文逗号隔开，但中间及前后不可有空格。
必须使用 `encodeURIComponent` 转义。

#### 4.3.4 (WebSocket) `path`
WebSocket 的路径。省略时默认为 `/`，但不可以为空字符串。**不推荐省略。**
必须使用 `encodeURIComponent` 转义。

#### 4.3.5 (WebSocket) `host`
WebSocket 请求时 `Host` 头的内容。**不推荐省略，不推荐设为空字符串。**
必须使用 `encodeURIComponent` 转义。

#### 4.3.6 (mKCP) `headerType`
mKCP 的伪装头部类型。当前可选值有 `none` / `srtp` / `utp` / `wechat-video` / `dtls` / `wireguard`。
省略时默认值为 `none`，即不使用伪装头部，但不可以为空字符串。

#### 4.3.7 (mKCP) `seed`
mKCP 种子。省略时不使用种子，但不可以为空字符串。**建议 mKCP 用户使用 `seed`。**
必须使用 `encodeURIComponent` 转义。

#### 4.3.8 (QUIC) `quicSecurity`
QUIC 的加密方式。当前可选值有 `none` / `aes-128-gcm` / `chacha20-poly1305`。
省略时默认值为 `none`。

#### 4.3.9 (QUIC) `key`
当 QUIC 的加密方式不为 `none` 时的加密密钥。
当 QUIC 的加密方式为 `none` 时，此项不得出现；否则，此项必须出现，且不可为空字符串。
若出现此项，则必须使用 `encodeURIComponent` 转义。

#### 4.3.10 (QUIC) `headerType`
QUIC 的伪装头部类型。其他同 mKCP `headerType` 字段定义。

#### 4.3.11 (gRPC) `serviceName`
对应 gRPC 的 ServiceName。建议仅使用英文字母数字和英文句号、下划线组成。
不建议省略，不可为空字符串。

#### 4.3.12 (gRPC) `mode`
对应 gRPC 的传输模式，目前有以下三种：
- `gun`: 即原始的 gun 传输模式，将单个 []byte 封在 Protobuf 里通过 gRPC 发送；
- `multi`: 即 Xray-Core 的 multiMode，将多组 []byte 封在一条 Protobuf 里通过 gRPC 发送；
- `guna`: 即通过使用自定义 Codec 的方式，直接将数据包封在 gRPC 里发送。
省略时默认为 `gun`，不可以为空字符串。

### 4.4 TLS 相关段

#### 4.4.1 `sni`
TLS SNI，对应配置文件中的 `serverName` 项目。
省略时复用 `remote-host`，但不可以为空字符串。

#### 4.4.2 `alpn`
TLS ALPN，对应配置文件中的 `alpn` 项目。
多个 ALPN 之间用英文逗号隔开，中间无空格。
省略时由内核决定具体行为，但不可以为空字符串。
必须使用 `encodeURIComponent` 转义。

#### 4.4.3 `allowInsecure`
**没有这个字段。** 不安全的节点，不适合分享。

#### 4.4.4 (XTLS) `flow`
XTLS 的流控方式。可选值为 `xtls-rprx-direct`、`xtls-rprx-splice` 等。
若使用 XTLS，此项不可省略，否则无此项。此项不可为空字符串。

## 5 举例

```
# VMess + TCP，不加密（仅作示例，不安全）
vmess://99c80931-f3f1-4f84-bffd-6eed6030f53d@qv2ray.net:31415?encryption=none#VMessTCPNaked

# VMess + TCP，自动选择加密
vmess://f08a563a-674d-4ffb-9f02-89d28aec96c9@qv2ray.net:9265#VMessTCPAuto

# VMess + TCP + TLS，内层不加密
vmess://136ca332-f855-4b53-a7cc-d9b8bff1a8d7@qv2ray.net:9323?encryption=none&security=tls#VMessTCPTLSNaked

# VLESS + TCP + XTLS
vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:3279?security=xtls&flow=xtls-rprx-splice#VLESSTCPXTLSSplice

# VLESS + mKCP + Seed
vless://399ce595-894d-4d40-add1-7d87f1a3bd10@qv2ray.net:50288?type=kcp&seed=69f04be3-d64e-45a3-8550-af3172c63055#VLESSmKCPSeed

# VMess + WebSocket + TLS
vmess://44efe52b-e143-46b5-a9e7-aadbfd77eb9c@qv2ray.net:6939?type=ws&security=tls&host=qv2ray.net&path=%2Fsomewhere#VMessWebSocketTLS
```

## 6 补充

### 6.1 2020/12/21 @RPRX 关于 `flow` 选项的补充说明

1. `-udp443` 系列属于客户端选项，**不建议**服务器下发，是否开启应由客户端决定。
2. `splice` 的使用场景比较苛刻，目前要求入站"纯粹"、且运行在 Linux / Android 操作系统上。

> @DuckSoft 的唠叨：
> 1. 目前 `splice` 与否对服务器方面没有要求，服务器使用 `direct` 即可支持 `splice` 和 `direct`。**建议**服务器下发 `direct`，开启 `splice` 与否应由客户端自行决定。
> 2. **必须充分认识到，XTLS 仍处于实验性阶段**，当前阶段分享链接的主要目标是**方便 XTLS 节点的交换与传播**，并不适用于机场大规模下发。

> Source: https://github.com/XTLS/Xray-core/issues/91
