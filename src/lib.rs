pub mod blacklist;
pub mod cli;
pub mod control_loop;
pub mod crowdsec_lapi;
pub mod metrics;
pub mod prometheus;
pub mod tracing_setup;
pub mod utils;
pub mod vyos_api;

use blacklist::BlacklistCache;
use crowdsec_lapi::CrowdsecLapiClient;
use vyos_api::VyosClient;

use self::blacklist::IpRangeMixed;

pub(crate) const USER_AGENT: &str = "vyos-crowdsec-bouncer/v0.0.1";

pub struct App {
    lapi: CrowdsecLapiClient,
    vyos: VyosClient,
    blacklist: BlacklistCache,
    config: Config,
}

pub struct Config {
    pub firewall_group: String,
    pub trusted_ips: IpRangeMixed,
    pub update_period: std::time::Duration,
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
