use std::time::Duration;

use ipnet::IpNet;

use super::types::{VyosCommandResponse, VyosConfigCommand};
use super::VyosSaveCommand;

#[allow(async_fn_in_trait)]
pub trait VyosApi {
    async fn set_firewall_groups(
        &self,
        commands: &[VyosConfigCommand],
        timeout: Option<Duration>,
    ) -> Result<(), anyhow::Error>;

    async fn save_config<'a>(
        &self,
        command: VyosSaveCommand,
        timeout: Option<Duration>,
    ) -> Result<(), anyhow::Error>;

    async fn retrieve_firewall_network_groups<'a>(
        &self,
        group_name: &str,
    ) -> Result<VyosCommandResponse<Vec<IpNet>>, anyhow::Error>;
}
