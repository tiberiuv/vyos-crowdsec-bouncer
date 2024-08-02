use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VyosConfigOperation {
    Set,
    Delete,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum VyosSaveOperation {
    Save,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum VyosGetOperation {
    ReturnValues,
}

#[derive(Debug, Serialize)]
pub struct VyosConfigCommand {
    pub op: VyosConfigOperation,
    pub path: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct VyosGetCommand {
    pub(super) op: VyosGetOperation,
    pub(super) path: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VyosCommandResponse<T> {
    pub success: bool,
    pub data: T,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VyosSaveCommand {
    pub(super) op: VyosSaveOperation,
}

impl VyosConfigCommand {
    pub(super) fn as_log_value(&self) -> String {
        format!("{:?} {}", self.op, self.path.last().unwrap())
    }
}

impl VyosConfigCommand {
    pub(super) fn new(op: VyosConfigOperation, path: Vec<String>) -> Self {
        Self { op, path }
    }
}

#[derive(Debug, Serialize)]
pub struct IpSet<'a>(pub &'a [IpAddr]);

impl<'a> IpSet<'a> {
    pub fn into_vyos_commands(
        self,
        op: VyosConfigOperation,
        firewall_group: &str,
    ) -> Vec<VyosConfigCommand> {
        self.0
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => VyosConfigCommand::new(
                    op,
                    format!(
                        "firewall group address-group {} address {}",
                        firewall_group, v4
                    )
                    .split(' ')
                    .map(ToOwned::to_owned)
                    .collect(),
                ),
                IpAddr::V6(v6) => VyosConfigCommand::new(
                    op,
                    format!(
                        "firewall group ipv6-address-group {} address {}",
                        firewall_group, v6,
                    )
                    .split(' ')
                    .map(ToOwned::to_owned)
                    .collect(),
                ),
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
pub struct NetSet<'a>(pub &'a [IpNet]);
impl<'a> NetSet<'a> {
    pub fn into_vyos_commands(
        self,
        op: VyosConfigOperation,
        firewall_group: &str,
    ) -> Vec<VyosConfigCommand> {
        self.0
            .iter()
            .map(|net| match net {
                IpNet::V4(v4) => VyosConfigCommand::new(
                    op,
                    format!(
                        "firewall group network-group {} network {}",
                        firewall_group, v4
                    )
                    .split(' ')
                    .map(ToOwned::to_owned)
                    .collect(),
                ),
                IpNet::V6(v6) => VyosConfigCommand::new(
                    op,
                    format!(
                        "firewall group ipv6-network-group {} network {}",
                        firewall_group, v6,
                    )
                    .split(' ')
                    .map(ToOwned::to_owned)
                    .collect(),
                ),
            })
            .collect()
    }
}
