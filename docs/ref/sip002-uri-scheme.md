# SIP002 URI scheme

Source: https://shadowsocks.org/doc/sip002.html

SIP002 proposed a new URI scheme, following [RFC3986](https://www.ietf.org/rfc/rfc3986.txt):

```
SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
userinfo = websafe-base64-encode-utf8(method  ":" password)
           method ":" password
```

Note that encoding `userinfo` with Base64URL is recommended but optional for Stream and AEAD (SIP004). But for AEAD-2022 (SIP022), `userinfo` MUST NOT be encoded with Base64URL. When `userinfo` is not encoded, `method` and `password` MUST be percent encoded.

The last `/` should be appended if plugin is present, but is optional if only tag is present. Example: `ss://cmVhbGl0eTpwYXNzd29yZA==@example.com:8888/?plugin=url-encoded-plugin-argument-value&unsupported-arguments=should-be-ignored#Dummy+profile+name`. This kind of URIs can be parsed by standard libraries provided by most languages.

For plugin argument, we use the similar format as `TOR_PT_SERVER_TRANSPORT_OPTIONS`, which have the format like `simple-obfs;obfs=http;obfs-host=example.com` where colons, semicolons, equal signs and backslashes MUST be escaped with a backslash.

Examples:

With user info encoded with Base64URL:

- `ss://cmVhbGl0eTpwYXNzd29yZA==@example.com:8888#Example1`
- `ss://cmVhbGl0eTpwYXNzd29yZA==@example.com:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2`

Plain user info:

- `ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@example.com:8888#Example3`
- `ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@example.com:8888/?plugin=v2ray-plugin%3Bserver#Example3`
