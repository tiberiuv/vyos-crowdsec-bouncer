pub mod blacklist;
pub mod cli;
pub mod crowdsec_lapi;
pub mod tracing;
pub mod utils;
pub mod vyos_api;

use std::sync::Arc;
use std::time::Duration;

use ::tracing::info;
use blacklist::IpRangeMixed;
use cli::Cli;
use crowdsec_lapi::types::DecisionsIpRange;
use crowdsec_lapi::{CrowdsecLAPI, CrowdsecLapiClient};
use vyos_api::{update_firewall, VyosApi, VyosClient};

use self::utils::inspect_err;

pub struct App {
    lapi: Arc<CrowdsecLapiClient>,
    vyos: Arc<VyosClient>,
    cli: Cli,
}

impl App {
    pub fn new(crowdsec_api: CrowdsecLapiClient, vyos_api: VyosClient, cli: Cli) -> Self {
        Self {
            lapi: Arc::new(crowdsec_api),
            vyos: Arc::new(vyos_api),
            cli,
        }
    }
}

pub async fn main_loop(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let trusted_ips = IpRangeMixed::from_nets(app.cli.trusted_ips.unwrap_or_default());

    let mut retries = 5;
    while retries != 0 {
        let new_decisions = app.lapi.stream_decisions(true).await.expect("fail");

        let existing_networks = (*app.vyos)
            .retrieve_firewall_network_groups(&app.cli.firewall_group)
            .await?;
        let existing_networks = IpRangeMixed::from_nets(existing_networks.data);

        let decision_ips = DecisionsIpRange::from(new_decisions)
            .filter_new(&trusted_ips)
            .filter_new(&existing_networks);

        if let Err(err) = update_firewall(
            &app.vyos,
            decision_ips,
            &app.cli.firewall_group,
            Some(Duration::from_secs(60 * 5)),
        )
        .await
        {
            inspect_err("Failed to update firewall", err);
        }
        retries -= 1;
    }

    loop {
        info!("Fetching decisions");
        let new_decisions = app.lapi.stream_decisions(false).await.expect("fail");
        let decision_ips = DecisionsIpRange::from(new_decisions).filter_new(&trusted_ips);

        if let Err(err) =
            update_firewall(&app.vyos, decision_ips, &app.cli.firewall_group, None).await
        {
            inspect_err("Failed to update firewall", err);
        }
        tokio::time::sleep(Duration::from_secs(app.cli.update_frequency_secs)).await;
    }
}
