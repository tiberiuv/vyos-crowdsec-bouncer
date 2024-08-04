use std::time::Duration;

use std::future::Future;

use ipnet::IpNet;

use super::types::{IpSet, VyosCommandResponse, VyosConfigCommand};

#[allow(async_fn_in_trait)]
pub trait VyosApi {
    async fn set_firewall_groups(
        &self,
        commands: &[VyosConfigCommand],
        timeout: Option<Duration>,
        save: bool,
    ) -> Result<(), anyhow::Error>;
    async fn retrieve_firewall_network_groups<'a>(
        &self,
        group_name: &str,
    ) -> Result<VyosCommandResponse<Vec<IpNet>>, anyhow::Error>;
    fn ban_ips<'a>(
        &self,
        fw_group_name: &str,
        ips: IpSet<'a>,
    ) -> impl Future<Output = Result<serde_json::Value, anyhow::Error>>;
    fn remove_ip_ban<'a>(
        &self,
        fw_group_name: &str,
        ips: IpSet<'a>,
    ) -> impl Future<Output = Result<serde_json::Value, anyhow::Error>>;
}
