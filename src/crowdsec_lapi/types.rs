use std::fmt::Display;
use std::net::IpAddr;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::blacklist::IpRangeMixed;
use crate::cli::ClientCerts;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(untagged)]
pub enum Origin {
    Cscli,
    Crowdsec,
    #[serde(rename = "CAPI")]
    Capi,
    Lists,
    Other(String),
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cscli => f.write_str("cscli"),
            Self::Crowdsec => f.write_str("crowdsec"),
            Self::Capi => f.write_str("CAPI"),
            Self::Lists => f.write_str("lists"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum Scope {
    Ip,
    Range,
    Other(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", untagged)]
#[allow(dead_code)]
pub enum DecisionType {
    Ban,
    Captcha,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// the duration of the decisions
    pub duration: String,
    /// (only relevant for GET ops) the unique id
    pub id: Option<i64>,
    /// the origin of the decision : cscli, crowdsec
    pub origin: Origin,
    pub scenario: String,
    /// the scope of decision : does it apply to an IP, a range, a username, etc
    pub scope: Scope,
    /// true if the decision result from a scenario in simulation mode
    pub simulated: Option<bool>,
    /// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
    #[serde(rename = "type")]
    pub type_: DecisionType,
    /// the date until the decisions must be active
    pub until: Option<DateTime<Utc>>,
    /// only relevant for LAPI->CAPI, ignored for cscli->LAPI and crowdsec->LAPI
    pub uuid: Option<String>,
    /// the value of the decision scope : an IP, a range, a username, etc
    pub value: String,
}

impl Decision {
    fn try_into_net(&self) -> Result<ipnet::IpNet, anyhow::Error> {
        if let Some(until) = self.until {
            let now = chrono::Utc::now();
            if until < now {
                return Err(anyhow!("decision skipped due to 'until' in the future"));
            }
        }
        let parsed = self.value.parse::<IpAddr>()?;
        Ok(match parsed {
            IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32)?),
            IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128)?),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecisionsResponse {
    pub new: Option<Vec<Decision>>,
    pub deleted: Option<Vec<Decision>>,
}

fn parse_crowdsec_decisions(decisions: Option<Vec<Decision>>) -> Vec<IpNet> {
    let (to_add, errors): (Vec<_>, Vec<_>) = decisions
        .unwrap_or_default()
        .iter()
        .map(Decision::try_into_net)
        .partition(|x| x.is_ok());
    if !errors.is_empty() {
        let errors: Vec<anyhow::Error> = errors.into_iter().map(|ip| ip.unwrap_err()).collect();
        error!(msg = "Error parsing ips from crowdsec decisions", ?errors);
    }
    to_add.into_iter().map(|ip| ip.unwrap()).collect()
}
impl From<DecisionsResponse> for DecisionsIpRange {
    fn from(value: DecisionsResponse) -> Self {
        Self {
            new: IpRangeMixed::from(parse_crowdsec_decisions(value.new)),
            deleted: IpRangeMixed::from(parse_crowdsec_decisions(value.deleted)),
        }
    }
}

#[derive(Debug)]
pub struct DecisionsIpRange {
    pub new: IpRangeMixed,
    pub deleted: IpRangeMixed,
}

impl DecisionsIpRange {
    pub fn filter_new(self, filter: &IpRangeMixed) -> Self {
        Self {
            // Only keep in new nets that are not in the filter
            new: self.new.exclude(filter),
            deleted: self.deleted,
        }
    }
    pub fn filter_deleted(self, filter: &IpRangeMixed) -> Self {
        Self {
            new: self.new,
            // Only keep in deleted nets that are already in the filter
            deleted: self.deleted.intersect(filter),
        }
    }
}

#[derive(Debug)]
pub struct DecisionsIps {
    pub new: Vec<IpAddr>,
    pub deleted: Vec<IpAddr>,
}

#[derive(Debug)]
pub struct DecisionsNets {
    pub new: Vec<IpNet>,
    pub deleted: Vec<IpNet>,
}

impl DecisionsIpRange {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.deleted.is_empty()
    }

    pub fn into_ips(&self) -> DecisionsIps {
        DecisionsIps {
            new: self.new.into_ips(),
            deleted: self.deleted.into_ips(),
        }
    }

    pub fn into_nets(&self) -> DecisionsNets {
        DecisionsNets {
            new: self.new.into_nets(),
            deleted: self.deleted.into_nets(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Add,
    Del,
    ReturnValues,
}

#[derive(Debug, Clone)]
pub struct CertAuth {
    pub root_ca: Certificate,
    pub identity: Identity,
}

#[derive(Debug, Clone)]
pub enum CrowdsecAuth {
    Apikey(String),
    Certs(CertAuth),
}

impl TryFrom<ClientCerts> for CertAuth {
    type Error = anyhow::Error;
    fn try_from(value: ClientCerts) -> Result<Self, Self::Error> {
        let mut pem = value.client_cert.clone();
        pem.extend_from_slice(&value.client_key);

        Ok(Self {
            root_ca: Certificate::from_pem(&value.ca_cert)?,
            identity: Identity::from_pem(&pem)?,
        })
    }
}

#[cfg(test)]
mod test {
    use ipnet::{Ipv4Net, Ipv6Net};
    use iprange::IpRange;

    use crate::blacklist::IpRangeMixed;

    use super::{Decision, DecisionsIpRange};

    fn ipv4(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }
    fn ipv4_range<'a, I: IntoIterator<Item = &'a str>>(i: I) -> IpRange<Ipv4Net> {
        IpRange::from_iter(i.into_iter().map(ipv4))
    }
    fn ipv6(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }
    fn ipv6_range<'a, I: IntoIterator<Item = &'a str>>(i: I) -> IpRange<Ipv6Net> {
        IpRange::from_iter(i.into_iter().map(ipv6))
    }

    #[test]
    fn deserializes_decision() {
        let serialized = r#"{"duration":"159h4m40.776506185s","id":22821676,"origin":"CAPI","scenario":"crowdsecurity/vpatch-connectwise-auth-bypass","scope":"Ip","type":"ban","value":"5.10.250.79"}"#;

        let _: Decision = serde_json::from_str(serialized).expect("failed to deserialize");
    }

    #[test]
    fn filter_added_decisions() {
        let decisions = DecisionsIpRange {
            new: IpRangeMixed {
                v4: ipv4_range(["192.168.0.1/32", "192.168.0.2/32"]),
                v6: ipv6_range(["fd00::1/128", "fd00::2/128"]),
            },
            deleted: Default::default(),
        };
        let filter = IpRangeMixed {
            v4: ipv4_range(["192.168.0.1/32"]),
            v6: ipv6_range(["fd00::1/128"]),
        };

        let actual = decisions.filter_new(&filter);

        let expected = IpRangeMixed {
            v4: ipv4_range(["192.168.0.2/32"]),
            v6: ipv6_range(["fd00::2/128"]),
        };

        assert_eq!(actual.new, expected);
        assert_eq!(actual.deleted, IpRangeMixed::default());
    }

    #[test]
    fn filter_deleted_decisions() {
        let new_dec = IpRangeMixed {
            v4: ipv4_range(["192.168.0.2/32"]),
            v6: ipv6_range(["fd00::2/128"]),
        };
        let decisions = DecisionsIpRange {
            new: new_dec.clone(),
            deleted: IpRangeMixed {
                v4: ipv4_range(["192.168.0.1/32", "10.10.10.10/32"]),
                v6: ipv6_range(["fd00::1/128", "fd00:ec2::1/128"]),
            },
        };
        let filter = IpRangeMixed {
            v4: ipv4_range(["192.168.0.1/32"]),
            v6: ipv6_range(["fd00::1/128"]),
        };

        let actual = decisions.filter_deleted(&filter);

        let expected = IpRangeMixed {
            v4: ipv4_range(["192.168.0.1/32"]),
            v6: ipv6_range(["fd00::1/128"]),
        };

        assert_eq!(actual.deleted, expected);
        assert_eq!(actual.new, new_dec);
    }
}
