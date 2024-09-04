mod http;
mod interface;
mod types;

use std::time::Duration;

use tracing::{debug, info, instrument};

pub use http::VyosClient;
pub use interface::VyosApi;
pub use types::{ipv4_group_get, ipv6_group_get, NetSet, VyosConfigOperation, VyosSaveCommand, VyosCommandResponse};

use crate::crowdsec_lapi::types::DecisionsIpRange;

#[instrument(skip(vyos_api, decisions_ip_range))]
pub async fn update_firewall(
    vyos_api: &VyosClient,
    decisions_ip_range: &DecisionsIpRange,
    firewall_group: &str,
    timeout: Option<Duration>,
) -> Result<(), anyhow::Error> {
    let decision_ips = decisions_ip_range.into_nets();
    debug!(msg = "Updating firewall groups", ?decision_ips);

    let mut commands =
        NetSet(&decision_ips.new).into_vyos_commands(VyosConfigOperation::Set, firewall_group);
    let mut remove_commands = NetSet(&decision_ips.deleted)
        .into_vyos_commands(VyosConfigOperation::Delete, firewall_group);
    commands.append(&mut remove_commands);

    const BATCH_SIZE: usize = 15000;
    for (idx, batch) in commands.chunks(BATCH_SIZE).enumerate() {
        info!("Setting batch {} {}", idx + 1, batch.len());
        vyos_api.set_firewall_groups(batch, timeout).await?;
        vyos_api
            .save_config(VyosSaveCommand::default(), timeout)
            .await?;
    }
    info!(
        added = decision_ips.new.len(),
        deleted = decision_ips.deleted.len()
    );

    Ok(())
}
