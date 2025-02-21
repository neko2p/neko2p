use crate::config::Config;
use common::Addr;
use std::str::FromStr;

#[derive(Default, Debug)]
pub struct Rule {
    rule_matchs: Vec<RuleMatch>,
    outbound: String,
}

#[derive(Debug)]
pub enum RuleMatch {
    IPv4Cidr { ip: [u8; 4], mask: usize },
    IPv6Cidr { ip: [u8; 16], mask: usize },
    Domain(String),
    DomainSuffix(String),
}

impl RuleMatch {
    pub fn is_match(&self, rule_query: &RuleQuery) -> bool {
        match rule_query {
            RuleQuery::Domain(domain) => match self {
                Self::Domain(domain_match) => domain == domain_match,
                Self::DomainSuffix(suffix) => domain.ends_with(suffix),
                _ => false,
            },
            RuleQuery::IPv4(ipv4) => match self {
                &Self::IPv4Cidr { ref ip, mut mask } => {
                    for (n, seg) in ip.iter().enumerate() {
                        let this_mask = u8::MAX << (8 - mask % 8);
                        if ipv4[n] & this_mask != *seg & this_mask {
                            return false;
                        }

                        if mask > 8 {
                            mask -= 8;
                        } else {
                            return true;
                        }
                    }
                    true
                }
                _ => false,
            },
            RuleQuery::IPv6(ipv6) => match self {
                &Self::IPv6Cidr { ref ip, mut mask } => {
                    for (n, seg) in ip.iter().enumerate() {
                        let this_mask = u8::MAX << (8 - mask % 8);
                        if ipv6[n] & this_mask != *seg & this_mask {
                            return false;
                        }

                        if mask > 8 {
                            mask -= 8;
                        } else {
                            return true;
                        }
                    }
                    true
                }
                _ => false,
            },
        }
    }
}

pub enum RuleQuery {
    Domain(String),
    IPv4([u8; 4]),
    IPv6([u8; 16]),
}

impl From<Addr> for RuleQuery {
    fn from(value: Addr) -> Self {
        match value {
            Addr::Domain(domain) => Self::Domain(domain.clone()),
            Addr::IPv4(ipv4) => Self::IPv4(ipv4),
            Addr::IPv6(ipv6) => {
                let mut octets = [0_u8; 16];
                for (i, octet) in octets.iter_mut().enumerate() {
                    if i % 2 == 0 {
                        *octet = (ipv6[i / 2] >> 8) as u8;
                    } else {
                        *octet = (ipv6[i / 2] & u8::MAX as u16) as u8;
                    }
                }
                Self::IPv6(octets)
            }
        }
    }
}

#[derive(Default, Debug)]
pub struct Router {
    rules: Vec<Rule>,
    final_outbound: String,
}

impl Router {
    pub fn from_config(config: &Config) -> Self {
        let mut router = Self::default();
        for config_rule in &config.route.rules {
            let mut rule = Rule {
                outbound: config_rule.outbound.clone(),
                ..Default::default()
            };
            if let Some(ips) = &config_rule.ipcidr {
                use std::net::IpAddr;

                for ip_with_mask in ips {
                    let ip = ip_with_mask.split('/').collect::<Vec<&str>>()[0];
                    let mask =
                        usize::from_str(ip_with_mask.split('/').collect::<Vec<&str>>()[1]).unwrap();
                    match IpAddr::from_str(ip).unwrap() {
                        IpAddr::V4(ip) => rule.rule_matchs.push(RuleMatch::IPv4Cidr {
                            ip: ip.octets(),
                            mask,
                        }),

                        IpAddr::V6(ip) => rule.rule_matchs.push(RuleMatch::IPv6Cidr {
                            ip: ip.octets(),
                            mask,
                        }),
                    }
                }
            }
            if let Some(domains) = &config_rule.domain {
                for domain in domains {
                    rule.rule_matchs.push(RuleMatch::Domain(domain.to_owned()));
                }
            }
            if let Some(domains) = &config_rule.domain_suffix {
                for domain in domains {
                    rule.rule_matchs
                        .push(RuleMatch::DomainSuffix(domain.to_owned()));
                }
            }

            router.rules.push(rule);
        }
        router.final_outbound = config.route.final_outbound.clone();

        router
    }
    /* Get outbount name by a rule query */
    pub fn get_outbound(&self, rule_query: RuleQuery) -> String {
        for rule in &self.rules {
            for rule_match in &rule.rule_matchs {
                if rule_match.is_match(&rule_query) {
                    return rule.outbound.clone();
                }
            }
        }
        self.final_outbound.clone()
    }
}
