use std::path::PathBuf;

use clap::{Args, Parser};
use ipnet::IpNet;
use reqwest::Url;

use crate::crowdsec_lapi::types::CrowdsecAuth;
use crate::utils::read_file;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long, env, num_args = 1..)]
    pub trusted_ips: Option<Vec<IpNet>>,

    #[arg(long, env = "UPDATE_FREQUENCY_SECS", default_value = "60")]
    pub update_frequency_secs: u64,

    #[arg(long, env = "VYOS_APIKEY")]
    pub vyos_apikey: String,

    #[arg(long, env = "VYOS_API")]
    pub vyos_api: Url,

    #[arg(long, env = "FIREWALL_GROUP", default_value = "CROWDSEC_BOUNCER")]
    pub firewall_group: String,

    #[arg(long, env = "CROWDSEC_API", default_value = "http://localhost:8080")]
    pub crowdsec_api: Url,

    #[command(flatten)]
    pub auth: Auth,
}

#[derive(Debug, Clone, Args)]
#[group(required = false, multiple = false)]
pub struct Auth {
    #[arg(long, env = "CROWDSEC_APIKEY")]
    pub crowdsec_apikey: Option<String>,

    #[command(flatten)]
    pub cert_auth: CertAuth,
}

#[derive(Debug, Args, Clone)]
#[group(required = false, multiple = true)]
pub struct CertAuth {
    #[arg(
        long,
        env = "CROWDSEC_ROOT_CA_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/ca.crt"
    )]
    crowdsec_root_ca_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/tls.crt"
    )]
    crowdsec_client_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_KEY",
        default_value = "/etc/crowdsec_bouncer/certs/tls.key"
    )]
    crowdsec_client_key: PathBuf,
}

impl CertAuth {
    fn exists(&self) -> bool {
        self.crowdsec_client_key.exists()
            && self.crowdsec_client_cert.exists()
            && self.crowdsec_root_ca_cert.exists()
    }
}

pub struct ClientCerts {
    pub ca_cert: Vec<u8>,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
}

impl TryFrom<CertAuth> for ClientCerts {
    type Error = anyhow::Error;
    fn try_from(value: CertAuth) -> Result<Self, Self::Error> {
        Ok(Self {
            ca_cert: read_file(&value.crowdsec_root_ca_cert)?,
            client_cert: read_file(&value.crowdsec_client_cert)?,
            client_key: read_file(&value.crowdsec_client_key)?,
        })
    }
}

impl TryFrom<Auth> for CrowdsecAuth {
    type Error = anyhow::Error;
    fn try_from(value: Auth) -> Result<Self, Self::Error> {
        if let Some(apikey) = value.crowdsec_apikey {
            Ok(Self::Apikey(apikey))
        } else if value.cert_auth.exists() {
            let certs = ClientCerts::try_from(value.cert_auth)?;
            Ok(Self::Certs(TryFrom::try_from(certs)?))
        } else {
            Err(anyhow::anyhow!("No authentication provided for vyos!"))
        }
    }
}
