use std::time::Duration;
use tracing::{error, info};

use crate::blacklist::{Blacklist, IpRangeMixed};
use crate::crowdsec_lapi::types::DecisionsIpRange;
use crate::crowdsec_lapi::CrowdsecLAPI;
use crate::utils::retry_op;
use crate::vyos_api::{update_firewall, VyosApi};
use crate::App;

pub async fn store_existing_blacklist(app: &App) -> Result<(), anyhow::Error> {
    let existing_networks = (*app.vyos)
        .retrieve_firewall_network_groups(&app.cli.firewall_group)
        .await?;

    let blacklist = Blacklist::new(IpRangeMixed::from(existing_networks.data));
    app.blacklist.store(blacklist);
    Ok(())
}

pub async fn do_iteration(
    app: &App,
    startup: bool,
    trusted_ips: &IpRangeMixed,
) -> Result<(), anyhow::Error> {
    info!("Fetching decisions");
    let new_decisions = app.lapi.stream_decisions(startup).await.expect("fail");

    if startup {
        store_existing_blacklist(app).await?;
    }

    let blacklist = app.blacklist.load();
    let decision_ips = DecisionsIpRange::from(new_decisions)
        .filter_new(trusted_ips)
        .filter_new(&blacklist.as_ref().ip_ranges)
        .filter_deleted(&blacklist.as_ref().ip_ranges);

    if let Err(err) = update_firewall(
        &app.vyos,
        &decision_ips,
        &app.cli.firewall_group,
        Some(Duration::from_secs(60 * 5)),
    )
    .await
    {
        error!(msg = "Failed to update firewall", ?err);
    } else {
        let new_blacklist = app
            .blacklist
            .load()
            .as_ref()
            .ip_ranges
            .merge(&decision_ips.new)
            .exclude(&decision_ips.deleted);
        app.blacklist.store(Blacklist::new(new_blacklist))
    };
    Ok(())
}

pub async fn main_loop(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let trusted_ips = IpRangeMixed::from(app.cli.trusted_ips.clone().unwrap_or_default());

    retry_op(5, || do_iteration(&app, true, &trusted_ips)).await?;

    loop {
        tokio::time::sleep(Duration::from_secs(app.cli.update_frequency_secs)).await;

        retry_op(10, || do_iteration(&app, true, &trusted_ips)).await?
    }
}
