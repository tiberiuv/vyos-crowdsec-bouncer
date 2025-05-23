mod http;
mod interface;
mod types;

use tracing::{info, instrument};

pub use http::VyosClient;
pub use interface::VyosApi;
pub use types::{
    ipv4_group_get, ipv6_group_get, NetSet, VyosCommandResponse, VyosConfigOperation,
    VyosSaveCommand,
};

use crate::crowdsec_lapi::types::{ipnets_for_log, DecisionsIpRange};
use crate::metrics::VYOS_COMMANDS_SENT_COUNTER;

#[instrument(skip(vyos_api, decisions_ip_range))]
pub async fn update_firewall(
    vyos_api: &VyosClient,
    decisions_ip_range: &DecisionsIpRange,
    firewall_group: &str,
    timeout: Option<std::time::Duration>,
    save_changes: bool,
) -> Result<(), anyhow::Error> {
    let decision_ips = decisions_ip_range.into_nets();
    info!(
        new = ipnets_for_log(&decision_ips.new),
        delete = ipnets_for_log(&decision_ips.deleted),
        "Updating firewall groups",
    );

    let mut commands =
        NetSet(&decision_ips.new).into_vyos_commands(VyosConfigOperation::Set, firewall_group);

    let mut remove_commands = NetSet(&decision_ips.deleted)
        .into_vyos_commands(VyosConfigOperation::Delete, firewall_group);
    commands.append(&mut remove_commands);
    VYOS_COMMANDS_SENT_COUNTER.inc_by(commands.len() as u64);

    const BATCH_SIZE: usize = 15000;
    for (idx, batch) in commands.chunks(BATCH_SIZE).enumerate() {
        info!("Setting batch {} {}", idx + 1, batch.len());
        vyos_api.set_firewall_groups(batch, timeout).await?;
        if save_changes {
            vyos_api.save_config(timeout).await?;
        }
    }
    info!(
        added = decision_ips.new.len(),
        deleted = decision_ips.deleted.len()
    );

    Ok(())
}
