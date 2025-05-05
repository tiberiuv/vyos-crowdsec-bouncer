use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::LazyLock;

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VyosCommand<'a> {
    Config(VyosConfigCommand<'a>),
    Get(VyosGetCommand<'a>),
    Save(VyosSaveCommand),
}

#[derive(Debug, Serialize)]
pub struct VyosConfigCommand<'a> {
    pub op: VyosConfigOperation,
    pub path: Vec<Cow<'a, str>>,
}

#[derive(Debug, Serialize)]
pub struct VyosGetCommand<'a> {
    pub op: VyosGetOperation,
    pub path: Vec<Cow<'a, str>>,
}
impl<'a> VyosGetCommand<'a> {
    pub fn new(path: impl IntoIterator<Item = Cow<'a, str>>) -> Self {
        Self {
            op: VyosGetOperation::ReturnValues,
            path: path.into_iter().collect(),
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

#[derive(Debug, Deserialize, Serialize)]
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

static FW_GROUP_PATH_GET: LazyLock<Vec<Cow<str>>> = LazyLock::new(|| {
    ["firewall", "group", "network-group", "", "network"]
        .into_iter()
        .map(Cow::from)
        .collect()
});
static FW_IPV6_GROUP_PATH_GET: LazyLock<Vec<Cow<str>>> = LazyLock::new(|| {
    ["firewall", "group", "ipv6-network-group", "", "network"]
        .into_iter()
        .map(Cow::from)
        .collect()
});
static FW_GROUP_PATH_SET: LazyLock<Vec<Cow<str>>> = LazyLock::new(|| {
    ["firewall", "group", "network-group", "", "network", ""]
        .into_iter()
        .map(Cow::from)
        .collect()
});
static FW_IPV6_GROUP_PATH_SET: LazyLock<Vec<Cow<str>>> = LazyLock::new(|| {
    ["firewall", "group", "ipv6-network-group", "", "network", ""]
        .into_iter()
        .map(Cow::from)
        .collect()
});

pub fn ipv4_group_get(fw_group: &str) -> VyosGetCommand {
    let mut path = FW_GROUP_PATH_GET.clone();
    path[3] = fw_group.into();

    VyosGetCommand::new(path)
}
pub fn ipv6_group_get(fw_group: &str) -> VyosGetCommand {
    let mut path = FW_IPV6_GROUP_PATH_GET.clone();
    path[3] = fw_group.into();

    VyosGetCommand::new(path)
}

fn ipv4_group_set(fw_group: &str, cidr: String) -> Vec<Cow<str>> {
    let mut path = (*FW_GROUP_PATH_SET).clone();
    path[3] = fw_group.into();
    path[5] = cidr.into();
    path
}
fn ipv6_group_set(fw_group: &str, cidr: String) -> Vec<Cow<str>> {
    let mut path = (*FW_IPV6_GROUP_PATH_SET).clone();
    path[3] = fw_group.into();
    path[5] = cidr.into();
    path
}

#[derive(Debug, Serialize)]
pub struct NetSet<'a>(pub &'a [IpNet]);
impl NetSet<'_> {
    pub fn into_vyos_commands(
        self,
        op: VyosConfigOperation,
        firewall_group: &str,
    ) -> Vec<VyosConfigCommand> {
        self.0
            .iter()
            .map(|net| match net {
                IpNet::V4(ip4) => {
                    VyosConfigCommand::new(op, ipv4_group_set(firewall_group, ip4.to_string()))
                }
                IpNet::V6(ip6) => {
                    VyosConfigCommand::new(op, ipv6_group_set(firewall_group, ip6.to_string()))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{NetSet, VyosConfigOperation};

    #[test]
    fn serialize_commands() {
        let add = vec![
            "127.0.0.1/32".parse().unwrap(),
            "fd00::1/128".parse().unwrap(),
        ];
        let delete = vec!["127.0.0.2/32".parse().unwrap()];
        let add = NetSet(&add);
        let delete = NetSet(&delete);

        let mut commands = add.into_vyos_commands(VyosConfigOperation::Set, "crowdsec");
        commands.append(&mut delete.into_vyos_commands(VyosConfigOperation::Delete, "crowdsec"));
        let actual = serde_json::to_string(&commands).unwrap();

        let expected = r#"[{"op":"set","path":["firewall","group","network-group","crowdsec","network","127.0.0.1/32"]},{"op":"set","path":["firewall","group","ipv6-network-group","crowdsec","network","fd00::1/128"]},{"op":"delete","path":["firewall","group","network-group","crowdsec","network","127.0.0.2/32"]}]"#;

        assert_eq!(actual, expected);
    }
}
