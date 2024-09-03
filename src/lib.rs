pub mod blacklist;
pub mod cli;
pub mod crowdsec_lapi;
pub mod main_loop;
pub mod tracing_setup;
pub mod utils;
pub mod vyos_api;

use blacklist::BlacklistCache;
use crowdsec_lapi::CrowdsecLapiClient;
use ipnet::IpNet;
use vyos_api::VyosClient;

pub(crate) const USER_AGENT: &str = "vyos-crowdsec-bouncer/v0.0.1";

pub struct App {
    lapi: CrowdsecLapiClient,
    vyos: VyosClient,
    blacklist: BlacklistCache,
    config: Config,
}

pub struct Config {
    pub firewall_group: String,
    pub trusted_ips: Vec<IpNet>,
    pub update_frequency_secs: u64,
}

impl App {
    pub fn new(crowdsec_api: CrowdsecLapiClient, vyos_api: VyosClient, config: Config) -> Self {
        Self {
            lapi: crowdsec_api,
            vyos: vyos_api,
            blacklist: BlacklistCache::default(),
            config,
        }
    }
}
