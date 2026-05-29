use serde::{Deserialize, Serialize};
use serde_yaml::{Value, Mapping, Number};
use std::collections::HashMap;

/// All supported proxy protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyNode {
    #[serde(rename = "ss")]
    Shadowsocks(ShadowsocksConfig),
    #[serde(rename = "ssr")]
    ShadowsocksR(ShadowsocksRConfig),
    #[serde(rename = "vmess")]
    VMess(VMessConfig),
    #[serde(rename = "trojan")]
    Trojan(TrojanConfig),
    #[serde(rename = "vless")]
    VLESS(VLESSConfig),
    #[serde(rename = "hysteria")]
    Hysteria(HysteriaConfig),
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2Config),
    #[serde(rename = "tuic")]
    Tuic(TuicConfig),
    #[serde(rename = "snell")]
    Snell(SnellConfig),
    #[serde(rename = "http")]
    Http(HttpConfig),
    #[serde(rename = "socks5")]
    Socks5(Socks5Config),
    #[serde(rename = "anytls")]
    AnyTLS(AnyTLSConfig),
}

/// Dedup key: server:port + credential hash
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct DedupKey {
    pub host: String,
    pub port: u16,
    pub cred_hash: String,
}

macro_rules! proxy_accessors {
    ($($variant:ident),+ $(,)?) => {
        impl ProxyNode {
            pub fn name(&self) -> &str {
                match self {
                    $( ProxyNode::$variant(c) => &c.name, )+
                }
            }
            pub fn set_name(&mut self, new_name: String) {
                match self {
                    $( ProxyNode::$variant(c) => c.name = new_name, )+
                }
            }
            pub fn host(&self) -> &str {
                match self {
                    $( ProxyNode::$variant(c) => &c.server, )+
                }
            }
            pub fn port(&self) -> u16 {
                match self {
                    $( ProxyNode::$variant(c) => c.port, )+
                }
            }
        }
    };
}

proxy_accessors!(
    Shadowsocks, ShadowsocksR, VMess, Trojan, VLESS,
    Hysteria, Hysteria2, Tuic, Snell, Http, Socks5, AnyTLS
);

impl ProxyNode {
    pub fn dedup_key(&self) -> DedupKey {
        use sha2::{Digest, Sha256};
        let cred_bytes = match self {
            ProxyNode::Shadowsocks(c) => c.password.as_deref().unwrap_or("").as_bytes(),
            ProxyNode::ShadowsocksR(c) => c.password.as_deref().unwrap_or("").as_bytes(),
            ProxyNode::VMess(c) => c.uuid.as_bytes(),
            ProxyNode::Trojan(c) => c.password.as_bytes(),
            ProxyNode::VLESS(c) => c.uuid.as_bytes(),
            ProxyNode::Hysteria(c) => c.auth_str.as_bytes(),
            ProxyNode::Hysteria2(c) => c.password.as_bytes(),
            ProxyNode::Tuic(c) => c.token.as_bytes(),
            ProxyNode::Snell(c) => c.psk.as_bytes(),
            ProxyNode::Http(c) => c.username.as_bytes(),
            ProxyNode::Socks5(c) => c.username.as_bytes(),
            ProxyNode::AnyTLS(c) => c.password.as_bytes(),
        };
        let hash = hex::encode(Sha256::digest(cred_bytes));
        DedupKey {
            host: self.host().to_string(),
            port: self.port(),
            cred_hash: hash,
        }
    }

    /// Build a complete Clash YAML mapping for this proxy node.
    /// Includes name/server/port/type + all protocol-specific fields.
    pub fn clash_mapping(&self) -> Mapping {
        match self {
            ProxyNode::Shadowsocks(c) => c.clash_mapping(),
            ProxyNode::ShadowsocksR(c) => c.clash_mapping(),
            ProxyNode::VMess(c) => c.clash_mapping(),
            ProxyNode::Trojan(c) => c.clash_mapping(),
            ProxyNode::VLESS(c) => c.clash_mapping(),
            ProxyNode::Hysteria(c) => c.clash_mapping(),
            ProxyNode::Hysteria2(c) => c.clash_mapping(),
            ProxyNode::Tuic(c) => c.clash_mapping(),
            ProxyNode::Snell(c) => c.clash_mapping(),
            ProxyNode::Http(c) => c.clash_mapping(),
            ProxyNode::Socks5(c) => c.clash_mapping(),
            ProxyNode::AnyTLS(c) => c.clash_mapping(),
        }
    }
}

macro_rules! proxy_fields {
    ($ty:ident { $($field:ident: $ft:ty),+ $(,)? }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $ty {
            pub name: String,
            pub server: String,
            pub port: u16,
            $(pub $field: $ft),+
        }
    };
}

proxy_fields!(ShadowsocksConfig {
    cipher: String,
    password: Option<String>,
    plugin: Option<String>,
    plugin_opts: Option<String>,
    udp: Option<bool>,
});

proxy_fields!(ShadowsocksRConfig {
    password: Option<String>,
    cipher: String,
    obfs: String,
    obfs_param: String,
    protocol: String,
    protocol_param: String,
    udp: Option<bool>,
});

proxy_fields!(VMessConfig {
    uuid: String,
    alter_id: Option<String>,
    cipher: Option<String>,
    tls: Option<bool>,
    skip_cert_verify: Option<bool>,
    servername: Option<String>,
    network: Option<String>,
    ws_path: Option<String>,
    ws_headers: Option<HashMap<String, String>>,
    udp: Option<bool>,
    packet_encoding: Option<String>,
});

proxy_fields!(TrojanConfig {
    password: String,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    skip_cert_verify: Option<bool>,
    udp: Option<bool>,
});

proxy_fields!(VLESSConfig {
    uuid: String,
    tls: Option<bool>,
    skip_cert_verify: Option<bool>,
    servername: Option<String>,
    network: Option<String>,
    ws_path: Option<String>,
    ws_headers: Option<HashMap<String, String>>,
    flow: Option<String>,
    packet_encoding: Option<String>,
});

proxy_fields!(HysteriaConfig {
    auth_str: String,
    protocol: Option<String>,
    up: Option<String>,
    down: Option<String>,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
    alpn: Option<Vec<String>>,
    obfs: Option<String>,
});

proxy_fields!(Hysteria2Config {
    password: String,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
    alpn: Option<Vec<String>>,
    obfs: Option<String>,
    obfs_password: Option<String>,
});

proxy_fields!(TuicConfig {
    token: String,
    ip: Option<String>,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
    alpn: Option<Vec<String>>,
    udp_relay_mode: Option<String>,
    congestion_controller: Option<String>,
});

proxy_fields!(SnellConfig {
    psk: String,
    obfs: Option<String>,
    version: Option<u8>,
});

proxy_fields!(HttpConfig {
    username: String,
    password: Option<String>,
    tls: Option<bool>,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
});

proxy_fields!(Socks5Config {
    username: String,
    password: Option<String>,
    tls: Option<bool>,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
    udp: Option<bool>,
});

proxy_fields!(AnyTLSConfig {
    password: String,
    sni: Option<String>,
    skip_cert_verify: Option<bool>,
    alpn: Option<Vec<String>>,
});

// ── Clash YAML Mapping for each config type ──────────────────────────────

impl ShadowsocksConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "ss".into());
        m.insert("cipher".into(), self.cipher.as_str().into());
        if let Some(ref v) = self.password { m.insert("password".into(), v.as_str().into()); }
        if let Some(ref v) = self.plugin { m.insert("plugin".into(), v.as_str().into()); }
        if let Some(ref v) = self.plugin_opts { m.insert("plugin-opts".into(), v.as_str().into()); }
        if let Some(v) = self.udp { m.insert("udp".into(), v.into()); }
        m
    }
}

impl ShadowsocksRConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "ssr".into());
        m.insert("cipher".into(), self.cipher.as_str().into());
        if let Some(ref v) = self.password { m.insert("password".into(), v.as_str().into()); }
        m.insert("obfs".into(), self.obfs.as_str().into());
        m.insert("protocol".into(), self.protocol.as_str().into());
        if !self.obfs_param.is_empty() { m.insert("obfs-param".into(), self.obfs_param.as_str().into()); }
        if !self.protocol_param.is_empty() { m.insert("protocol-param".into(), self.protocol_param.as_str().into()); }
        if let Some(v) = self.udp { m.insert("udp".into(), v.into()); }
        m
    }
}

impl VMessConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "vmess".into());
        m.insert("uuid".into(), self.uuid.as_str().into());
        if let Some(ref v) = self.alter_id { m.insert("alterId".into(), v.as_str().into()); }
        if let Some(ref v) = self.cipher { m.insert("cipher".into(), v.as_str().into()); }
        if let Some(v) = self.tls { m.insert("tls".into(), v.into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.servername { m.insert("servername".into(), v.as_str().into()); }
        if let Some(ref v) = self.network { m.insert("network".into(), v.as_str().into()); }
        if let Some(ref v) = self.ws_path { m.insert("ws-path".into(), v.as_str().into()); }
        if let Some(ref h) = self.ws_headers { if let Some(host) = h.get("Host") {
            let mut hm = Mapping::new();
            hm.insert("Host".into(), host.as_str().into());
            m.insert("ws-headers".into(), Value::Mapping(hm));
        }}
        if let Some(v) = self.udp { m.insert("udp".into(), v.into()); }
        if let Some(ref v) = self.packet_encoding { m.insert("packet-encoding".into(), v.as_str().into()); }
        m
    }
}

impl TrojanConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "trojan".into());
        m.insert("password".into(), self.password.as_str().into());
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(ref v) = self.alpn {
            m.insert("alpn".into(), Value::Sequence(v.iter().map(|s| Value::String(s.clone())).collect()));
        }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(v) = self.udp { m.insert("udp".into(), v.into()); }
        m
    }
}

impl VLESSConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "vless".into());
        m.insert("uuid".into(), self.uuid.as_str().into());
        if let Some(v) = self.tls { m.insert("tls".into(), v.into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.servername { m.insert("servername".into(), v.as_str().into()); }
        if let Some(ref v) = self.network { m.insert("network".into(), v.as_str().into()); }
        if let Some(ref v) = self.ws_path { m.insert("ws-path".into(), v.as_str().into()); }
        if let Some(ref h) = self.ws_headers { if let Some(host) = h.get("Host") {
            let mut hm = Mapping::new();
            hm.insert("Host".into(), host.as_str().into());
            m.insert("ws-headers".into(), Value::Mapping(hm));
        }}
        if let Some(ref v) = self.flow { m.insert("flow".into(), v.as_str().into()); }
        if let Some(ref v) = self.packet_encoding { m.insert("packet-encoding".into(), v.as_str().into()); }
        m
    }
}

impl HysteriaConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "hysteria".into());
        m.insert("auth_str".into(), self.auth_str.as_str().into());
        if let Some(ref v) = self.protocol { m.insert("protocol".into(), v.as_str().into()); }
        if let Some(ref v) = self.up { m.insert("up".into(), v.as_str().into()); }
        if let Some(ref v) = self.down { m.insert("down".into(), v.as_str().into()); }
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.alpn {
            m.insert("alpn".into(), Value::Sequence(v.iter().map(|s| Value::String(s.clone())).collect()));
        }
        if let Some(ref v) = self.obfs { m.insert("obfs".into(), v.as_str().into()); }
        m
    }
}

impl Hysteria2Config {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "hysteria2".into());
        m.insert("password".into(), self.password.as_str().into());
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.obfs { m.insert("obfs".into(), v.as_str().into()); }
        if let Some(ref v) = self.obfs_password { m.insert("obfs-password".into(), v.as_str().into()); }
        if let Some(ref v) = self.alpn {
            m.insert("alpn".into(), Value::Sequence(v.iter().map(|s| Value::String(s.clone())).collect()));
        }
        m
    }
}

impl TuicConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "tuic".into());
        m.insert("token".into(), self.token.as_str().into());
        if let Some(ref v) = self.ip { m.insert("ip".into(), v.as_str().into()); }
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.alpn {
            m.insert("alpn".into(), Value::Sequence(v.iter().map(|s| Value::String(s.clone())).collect()));
        }
        if let Some(ref v) = self.udp_relay_mode { m.insert("udp-relay-mode".into(), v.as_str().into()); }
        if let Some(ref v) = self.congestion_controller { m.insert("congestion-controller".into(), v.as_str().into()); }
        m
    }
}

impl SnellConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "snell".into());
        m.insert("psk".into(), self.psk.as_str().into());
        if let Some(ref v) = self.obfs { m.insert("obfs".into(), v.as_str().into()); }
        if let Some(v) = self.version { m.insert("version".into(), Value::Number(Number::from(v))); }
        m
    }
}

impl HttpConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "http".into());
        m.insert("username".into(), self.username.as_str().into());
        if let Some(ref v) = self.password { m.insert("password".into(), v.as_str().into()); }
        if let Some(v) = self.tls { m.insert("tls".into(), v.into()); }
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        m
    }
}

impl Socks5Config {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "socks5".into());
        m.insert("username".into(), self.username.as_str().into());
        if let Some(ref v) = self.password { m.insert("password".into(), v.as_str().into()); }
        if let Some(v) = self.tls { m.insert("tls".into(), v.into()); }
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(v) = self.udp { m.insert("udp".into(), v.into()); }
        m
    }
}

impl AnyTLSConfig {
    fn clash_mapping(&self) -> Mapping {
        let mut m = Mapping::new();
        m.insert("name".into(), self.name.as_str().into());
        m.insert("server".into(), self.server.as_str().into());
        m.insert("port".into(), Value::Number(Number::from(self.port)));
        m.insert("type".into(), "anytls".into());
        m.insert("password".into(), self.password.as_str().into());
        if let Some(ref v) = self.sni { m.insert("sni".into(), v.as_str().into()); }
        if let Some(v) = self.skip_cert_verify { m.insert("skip-cert-verify".into(), v.into()); }
        if let Some(ref v) = self.alpn {
            m.insert("alpn".into(), Value::Sequence(v.iter().map(|s| Value::String(s.clone())).collect()));
        }
        m
    }
}

// ── Enriched Proxy (carries latency + geo info through pipeline) ──────────

#[derive(Debug, Clone)]
pub struct EnrichedProxy {
    pub node: ProxyNode,
    pub latency_ms: u64,
    pub country_code: String,
    pub country_name: String,
    pub emoji: String,
}

impl EnrichedProxy {
    pub fn new(node: ProxyNode, latency_ms: u64) -> Self {
        Self {
            node,
            latency_ms,
            country_code: String::new(),
            country_name: String::new(),
            emoji: String::new(),
        }
    }

    pub fn attach_geo(&mut self, geo: &crate::geoip::GeoInfo) {
        self.country_code = geo.country_code.clone();
        self.country_name = geo.country_name.clone();
        self.emoji = geo.emoji.clone();
    }
}
