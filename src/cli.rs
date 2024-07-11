use cidr::AnyIpCidr;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Add,
    Del,
    ReturnValues,
}

impl From<Operation> for crate::crowdsec_lapi::Operation {
    fn from(value: Operation) -> Self {
        match value {
            Operation::ReturnValues => Self::ReturnValues,
            Operation::Add => Self::Add,
            Operation::Del => Self::Del,
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Bin {
    #[arg(short, long = "trusted-ips", num_args = 1..)]
    trusted_ips: Option<Vec<AnyIpCidr>>,

    #[arg(short, long, default_value_t = 1)]
    count: u8,

    #[arg(long, env = "VYOS_APIKEY")]
    vyos_apikey: String,

    #[arg(long, env = "FIREWALL_GROUP", default_value = "CROWDSEC_BOUNCER")]
    firewall_group: Option<String>,
}
