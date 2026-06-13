# QR code scheme

Source: https://github.com/ShadowsocksR-Live/shadowsocksr-native/wiki/QR-code-scheme

## 基本定义

采用 `base64` 且 [URL safe](https://zh.wikipedia.org/wiki/Base64#%E5%9C%A8URL%E4%B8%AD%E7%9A%84%E5%BA%94%E7%94%A8) 作为 scheme, 且不带 `padding` (没有末尾的等于号), 具体格式如下：

```
ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0&ot_enable=0&ot_domain=base64domain&ot_path=base64path&dangerous_mode=false)
```

其中, `base64pass` 及之前以 `:` 分隔的, 不可省略, 而 `/?` 及其后面的内容, 可按需要写上.

对 `over TLS` 的相关信息是 `ot_enable`, `ot_domain`, `ot_path`, `dangerous_mode`.

如果啓用 `dangerous_mode` 模式（ dangerous_mode 項存在且其值爲 `true`），則客戶端不再進行證書驗證，這有可能遭到中間人攻擊，但好處是免除了冗長的根證書文件的攜帶, 還能夠編碼成 QRcode 方便分享.

字符串使用 `UTF8` 編碼, 編碼後必須以 `urlsafebase64` 編碼，包括 密碼、混淆參數、協議參數、備註、group、ot_domain、ot_path.

`udpport` 參數及 `uot` 目前沒有使用, 也許永遠不會使用了.

示例：

```
服務器IP： 127.0.0.1
端口： 1234
密碼： aaabbb
加密： aes-128-cfb
協議： auth_aes128_md5
協議參數： （空）
混淆： tls1.2_ticket_auth
混淆參數： breakwa11.moe
備註： 測試中文
```

生成的帶備註結果： `ssr://MTI3LjAuMC4xOjEyMzQ6YXV0aF9hZXMxMjhfbWQ1OmFlcy0xMjgtY2ZiOnRsczEuMl90aWNrZXRfYXV0aDpZV0ZoWW1KaS8_b2Jmc3BhcmFtPVluSmxZV3QzWVRFeExtMXZaUSZyZW1hcmtzPTVyV0w2Sy1WNUxpdDVwYUg`

生成的不帶備註的標準結果（結果唯一）： `ssr://MTI3LjAuMC4xOjEyMzQ6YXV0aF9hZXMxMjhfbWQ1OmFlcy0xMjgtY2ZiOnRsczEuMl90aWNrZXRfYXV0aDpZV0ZoWW1KaS8_b2Jmc3BhcmFtPVluSmxZV3QzWVRFeExtMXZaUQ`

多連結組合用於同時導入或導出多個鏈接使用，標準導出格式形如：

```
ssr://aaa
ssr://bbb
ssr://ccc
```

或者

```
ssr://aaa ssr://bbb ssr://ccc
```
