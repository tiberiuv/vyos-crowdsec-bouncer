use std::str::FromStr;

use anyhow::anyhow;
use cidr::AnyIpCidr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Origin {
    Cscli,
    Crowdsec
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// the duration of the decisions
    pub duration: String,
    /// (only relevant for GET ops) the unique id
    pub id: Option<i64>,
    /// the origin of the decision : cscli, crowdsec
    pub origin: String,
    pub scenario: String,
    /// the scope of decision : does it apply to an IP, a range, a username, etc
    pub scope: String,
    /// true if the decision result from a scenario in simulation mode
    pub simulated: Option<bool>,
    /// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
    #[serde(rename = "type")]
    pub type_: String,
    /// the date until the decisions must be active
    pub until: Option<String>,
    /// only relevant for LAPI->CAPI, ignored for cscli->LAPI and crowdsec->LAPI
    pub uuid: Option<String>,
    /// the value of the decision scope : an IP, a range, a username, etc
    pub value: String,
}

impl Decision {
    pub fn from_crowdsec_input(s: &str) -> Result<Self, anyhow::Error> {
        if let Some(a) =  s.split_whitespace().take(5).last() {
            Ok(serde_json::from_str(a)?)
        } else {
            Err(anyhow!("Json payload not provided as arg 5"))
        }
    }
}

#[derive(Debug, Clone, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Add,
    Del,
    ReturnValues,
}

type Seconds = u64;
#[derive(Debug, Deserialize)]
struct CrowdsecInputDecision {
    operation: Operation,
    ip: AnyIpCidr,
    duration_seconds: Seconds,
    reason: String,
    decision: Decision,
}

/* impl FromStr for Decision {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
    }
} */
