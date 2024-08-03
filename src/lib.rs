pub mod blacklist;
pub mod cli;
pub mod crowdsec_lapi;
pub mod main_loop;
pub mod tracing;
pub mod utils;
pub mod vyos_api;

use std::sync::Arc;

use blacklist::BlacklistCache;
use cli::Cli;
use crowdsec_lapi::CrowdsecLapiClient;
use vyos_api::VyosClient;

pub struct App {
    lapi: Arc<CrowdsecLapiClient>,
    vyos: Arc<VyosClient>,
    cli: Cli,
    blacklist: BlacklistCache,
}

impl App {
    pub fn new(crowdsec_api: CrowdsecLapiClient, vyos_api: VyosClient, cli: Cli) -> Self {
        Self {
            lapi: Arc::new(crowdsec_api),
            vyos: Arc::new(vyos_api),
            cli,
            blacklist: BlacklistCache::default(),
        }
    }
}
