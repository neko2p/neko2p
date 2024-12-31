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
}

impl Outbound {
    pub fn get_name(&self) -> &str {
        match self {
            Self::Direct { name } => name,
            Self::Reject { name } => name,
            Self::Trojan {
                name,
                server: _,
                port: _,
                password: _,
                tls: _,
            } => name,
            Self::Shadowsocks {
                name,
                server: _,
                port: _,
                password: _,
                cipher: _,
            } => name,
            Self::Vless {
                name,
                server: _,
                port: _,
                uuid: _,
            } => name,
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
