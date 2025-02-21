#![allow(dead_code)]
use serde::Deserialize;

pub const TLS_INSECURE_DEFAULT: bool = false;

#[derive(Debug, Deserialize, Clone)]
pub struct Nameserver {
    server: String,
    name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Dns {
    pub servers: Vec<Nameserver>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Inbound {
    #[serde(rename = "socks5")]
    Socks5 { listen: String, port: u16 },
    #[serde(rename = "tun")]
    Tun { address: String },
    #[serde(rename = "trojan")]
    Trojan {
        listen: String,
        port: u16,
        passwords: Vec<String>,
        tls: TLSSetting,
    },
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        listen: String,
        port: u16,
        method: String,
        password: String,
    },
    #[serde(rename = "vless")]
    Vless {
        listen: String,
        port: u16,
        uuids: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Outbound {
    #[serde(rename = "direct")]
    Direct { name: String },
    #[serde(rename = "reject")]
    Reject { name: String },
    #[serde(rename = "socks5")]
    Socks5 {
        name: String,
        server: String,
        port: u16,
    },
    #[serde(rename = "trojan")]
    Trojan {
        name: String,
        server: String,
        port: u16,
        password: String,
        tls: Option<TLSSetting>,
    },
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        name: String,
        server: String,
        port: u16,
        password: String,
        method: String,
    },
    #[serde(rename = "vmess")]
    Vmess {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        tls: Option<TLSSetting>,
    },
    #[serde(rename = "vless")]
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        tls: Option<TLSSetting>,
    },
    #[serde(rename = "hysteria2")]
    Hysteria2 {
        name: String,
        server: String,
        port: u16,
        password: String,
        tls: Option<TLSSetting>,
    },
    #[serde(rename = "ssh")]
    Ssh {
        name: String,
        server: String,
        port: u16,
        username: String,
        password: Option<String>,
        private_key_path: Option<String>,
        private_key_passphrase: Option<String>,
    },
}

impl Outbound {
    pub fn get_name(&self) -> &str {
        match self {
            Self::Direct { name } => name,
            Self::Reject { name } => name,
            Self::Socks5 { name, .. } => name,
            Self::Trojan { name, .. } => name,
            Self::Shadowsocks { name, .. } => name,
            Self::Vmess { name, .. } => name,
            Self::Vless { name, .. } => name,
            Self::Hysteria2 { name, .. } => name,
            Self::Ssh { name, .. } => name,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TLSSetting {
    pub insecure: Option<bool>,
    pub sni: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RuleItem {
    pub ipcidr: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    #[serde(rename = "domain-suffix")]
    pub domain_suffix: Option<Vec<String>>,
    pub outbound: String,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    pub rules: Vec<RuleItem>,
    #[serde(rename = "final")]
    pub final_outbound: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub dns: Dns,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
}
