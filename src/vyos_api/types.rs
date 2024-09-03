use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub enum VyosCommand {
    Config(VyosConfigCommand),
    Get(VyosGetOperation),
    Save(VyosSaveCommand),
}

#[derive(Debug, Serialize)]
pub struct VyosConfigCommand {
    pub op: VyosConfigOperation,
    pub path: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VyosGetCommand {
    pub op: VyosGetOperation,
    pub path: Vec<String>,
}
impl VyosGetCommand {
    pub fn new(path: Vec<String>) -> Self {
        Self {
            op: VyosGetOperation::ReturnValues,
            path,
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct VyosSaveCommand {
    pub op: VyosSaveOperation,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VyosConfigOperation {
    Set,
    Delete,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum VyosSaveOperation {
    #[default]
    Save,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VyosGetOperation {
    ReturnValues,
}

#[derive(Debug, Deserialize)]
pub struct VyosCommandResponse<T> {
    pub success: bool,
    pub data: T,
    pub error: Option<String>,
}

impl VyosConfigCommand {
    pub(super) fn new(op: VyosConfigOperation, path: Vec<String>) -> Self {
        Self { op, path }
    }
}

fn ipv4_fw_group_path(group: &str) -> Vec<String> {
    format!("firewall group network-group {} network", group)
        .split(' ')
        .map(ToOwned::to_owned)
        .collect()
}
fn ipv6_fw_group_path(group: &str) -> Vec<String> {
    format!("firewall group ipv6-network-group {} network", group)
        .split(' ')
        .map(ToOwned::to_owned)
        .collect()
}

pub fn ipv4_group_get(group: &str) -> VyosGetCommand {
    let path = ipv4_fw_group_path(group);
    VyosGetCommand::new(path)
}
pub fn ipv6_group_get(group: &str) -> VyosGetCommand {
    let path = ipv6_fw_group_path(group);
    VyosGetCommand::new(path)
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
