use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::LazyLock;

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub enum VyosCommand<'a> {
    Config(VyosConfigCommand<'a>),
    Get(VyosGetOperation),
    Save(VyosSaveCommand),
}

#[derive(Debug, Serialize)]
pub struct VyosConfigCommand<'a> {
    pub op: VyosConfigOperation,
    pub path: Vec<Cow<'a, str>>,
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

impl<'a> VyosConfigCommand<'a> {
    pub(super) fn new(op: VyosConfigOperation, path: Vec<Cow<'a, str>>) -> Self {
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

static FIREWALL_NETWORK_GROUP: LazyLock<Vec<Cow<str>>> = LazyLock::new(|| {
    ["firewall", "group", "network-group", "", "network", ""]
        .into_iter()
        .map(Cow::from)
        .collect()
});

fn firewall_network_group(fw_group: &str, cidr: String) -> Vec<Cow<str>> {
    let mut path = (*FIREWALL_NETWORK_GROUP).clone();
    path[3] = fw_group.into();
    path[5] = cidr.into();
    path
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
            .map(|net| {
                VyosConfigCommand::new(op, firewall_network_group(firewall_group, net.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{NetSet, VyosConfigOperation};

    #[test]
    fn serialize_commands() {
        let list = vec![
            "127.0.0.1/32".parse().unwrap(),
            "127.0.0.2/32".parse().unwrap(),
        ];
        let netset = NetSet(&list);

        let actual =
            serde_json::to_string(&netset.into_vyos_commands(VyosConfigOperation::Set, "group"))
                .unwrap();

        let expected = r#"[{"op":"set","path":["firewall","group","network-group","group","network","127.0.0.1/32"]},{"op":"set","path":["firewall","group","network-group","group","network","127.0.0.2/32"]}]"#;

        assert_eq!(actual, expected);
    }
}
