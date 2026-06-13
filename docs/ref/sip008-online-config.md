# SIP008 Online Configuration Delivery

Source: https://shadowsocks.org/doc/sip008.html

This specification defines a standard JSON document format for online configuration sharing and delivery, along with guidelines and security considerations for the secure transport of server configurations.

## JSON Document Format

An example of a standard SIP008 JSON document:

```json
{
    "version": 1,
    "servers": [
        {
            "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
            "remarks": "Name of the server",
            "server": "example.com",
            "server_port": 8388,
            "password": "example",
            "method": "chacha20-ietf-poly1305",
            "plugin": "xxx",
            "plugin_opts": "xxxxx"
        },
        {
            "id": "7842c068-c667-41f2-8f7d-04feece3cb67",
            "remarks": "Name of the server",
            "server": "example.com",
            "server_port": 8388,
            "password": "example",
            "method": "chacha20-ietf-poly1305",
            "plugin": "xxx",
            "plugin_opts": "xxxxx"
        }
    ],
    "bytes_used": 274877906944,
    "bytes_remaining": 824633720832
}
```

- All fields listed above, unless specified otherwise, are mandatory.
- The root object must contain a `version` field and it's set to `1` for this version.
- Each object within the `servers` array must represent a valid Shadowsocks server.
- The `id` field is a randomly-generated UUID used as the server UUID.
- If a server does not use a plugin, the `plugin` and `plugin_opts` should be empty or excluded.
- To report data usage metrics, use the optional `bytes_used` and `bytes_remaining` fields.
- The `bytes_used` field represents data used by the user in bytes.
- The `bytes_remaining` field represents data remaining. If no data limit is in place, the field must be omitted.

## Transport and Delivery

- Delivery must use HTTPS as the transport protocol.
- Clients must not ignore certificate issues or TLS handshake errors.
- A delivery URL should employ basic protections against crawling.
- The response must be a standard JSON document with `Content-Type: application/json; charset=utf-8`.
