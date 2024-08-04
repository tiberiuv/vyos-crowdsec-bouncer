pub mod blacklist;
pub mod cli;
pub mod crowdsec_lapi;
pub mod main_loop;
pub mod tracing_setup;
pub mod utils;
pub mod vyos_api;

use blacklist::BlacklistCache;
use cli::Cli;
use crowdsec_lapi::CrowdsecLapiClient;
use vyos_api::VyosClient;

pub struct App {
    lapi: CrowdsecLapiClient,
    vyos: VyosClient,
    cli: Cli,
    blacklist: BlacklistCache,
}

impl App {
    pub fn new(crowdsec_api: CrowdsecLapiClient, vyos_api: VyosClient, cli: Cli) -> Self {
        Self {
            lapi: crowdsec_api,
            vyos: vyos_api,
            cli,
            blacklist: BlacklistCache::default(),
        }
    }
}
