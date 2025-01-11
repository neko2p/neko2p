use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Inbound {
    pub r#type: String,
    pub listen: String,
    pub port: u16,
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
        cipher: String,
    },
    #[serde(rename = "vless")]
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: String,
    },
    #[serde(rename = "hysteria2")]
    Hysteria2 {
        name: String,
        server: String,
        port: u16,
        password: String,
        tls: Option<TLSSetting>,
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
            Self::Vless { name, .. } => name,
            Self::Hysteria2 { name, .. } => name,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TLSSetting {
    pub insecure: Option<bool>,
    pub sni: Option<String>,
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
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
}
