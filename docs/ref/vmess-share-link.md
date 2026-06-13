# VMess 分享链接说明

Source: https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link

## 分享的链接格式

```
vmess://(Base64 编码的 JSON 格式配置文件数据)
```

JSON 数据如下

```json
{
    "v": "2",
    "ps": "备注或别名",
    "add": "111.111.111.111",
    "port": "32000",
    "id": "1386f85e-657b-4d6e-9d56-78badb75e1fd",
    "aid": "100",
    "scy": "zero",
    "net": "tcp",
    "type": "none",
    "host": "www.bbb.com",
    "path": "/",
    "tls": "tls",
    "sni": "www.ccc.com",
    "alpn": "h2",
    "fp": "chrome"
}
```

## 属性详细说明

| 字段 | 说明 |
|------|------|
| v | 配置文件版本号，主要用来识别当前配置 |
| ps | 备注或别名 |
| add | 地址IP或域名 |
| port | 端口号 |
| id | UUID |
| aid | alterId |
| scy | 加密方式(security)，没有时默认auto |
| net | 传输协议(tcp/kcp/ws/h2/quic) |
| type | 伪装类型(none/http/srtp/utp/wechat-video) *tcp or kcp or QUIC |
| host | 伪装的域名：1. http(tcp)->host逗号(,)隔开；2. ws->host；3. h2->host；4. QUIC->securty |
| path | path：1. ws->path；2. h2->path；3. QUIC->key/Kcp->seed；4. grpc->serviceName |
| tls | 传输层安全(tls) |
| sni | serverName |
| alpn | h2,http/1.1 |
| fp | fingerprint |
