# Hysteria 2 URI Scheme

Source: https://v2.hysteria.network/docs/developers/URI-Scheme

The Hysteria 2 URI scheme is designed to provide a compact representation of the necessary information for connecting to a Hysteria 2 server. It captures various parameters such as server address, authentication details, obfuscation type and parameters, TLS settings.

## Structure

```
hysteria2://[auth@]hostname[:port]/?[key=value]&[key=value]...
```

Alternative scheme: `hy2://[auth@]hostname[:port]/?[key=value]&[key=value]...`

## Components

### Scheme

`hysteria2` or `hy2`

### Auth

Authentication credentials should be specified in the `auth` component of the URI. This is essentially the username part of the standard URI format, and therefore needs to be percent-encoded if it contains special characters.

A special case is when the server uses the `userpass` authentication, in which case the `auth` component should be formatted as `username:password`.

### Hostname

The hostname and optional port of the server. If the port is omitted, it defaults to 443.

The port part supports the "multi-port" format:
- `example.com:1234,5678,9012`
- `example.com:20000-50000`
- `example.com:1234,5000-6000,7044,8000-9000`

### Query parameters

| Parameter | Description |
|-----------|-------------|
| `obfs` | Obfuscation type: `salamander` or `gecko` |
| `obfs-password` | Password for the obfuscation |
| `sni` | Server Name Indication for TLS |
| `insecure` | Allow insecure TLS: `1`=true, `0`=false |
| `pinSHA256` | Pinned SHA-256 fingerprint of server certificate |

## Example

```
hysteria2://letmein@example.com:123,5000-6000/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com
```

## Realm mode

```
hysteria2+realm://<token>@<rendezvous-host>[:port]/<realm-name>?[key=value]&[key=value]...
```

Additional parameters for realm mode:
- `auth`: Hysteria authentication credentials
- `stun`: Override STUN servers (repeat for multiple)
- `lport`: Bind local UDP socket to specific source port (1-65535)

## Implementation notes

The URI is intentionally designed to contain only the essential information needed to connect to a Hysteria 2 server. Parameters should never include client modes (HTTP, SOCKS5, etc.) or bandwidth values.
