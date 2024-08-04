use std::future::Future;
use std::time::Duration;

use ipnet::IpNet;
use reqwest::multipart::Form;
use reqwest::{Client, StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use tracing::instrument;

use super::interface::VyosApi;
use super::types::{
    IpSet, VyosCommandResponse, VyosConfigCommand, VyosConfigOperation, VyosGetCommand,
    VyosGetOperation, VyosSaveCommand, VyosSaveOperation,
};

#[derive(Debug)]
pub struct VyosClient {
    client: Client,
    host: Url,
    apikey: String,
}

impl VyosClient {
    pub fn new(host: Url, apikey: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .use_rustls_tls()
            .build()
            .expect("failed to build client");
        Self {
            client,
            host,
            apikey,
        }
    }
}

impl VyosClient {
    fn url(&self, path: &str) -> Url {
        self.host.join(path).expect("invalid url")
    }

    async fn send<T: DeserializeOwned, P: Serialize>(
        &self,
        path: &str,
        payload: P,
        timeout: Option<Duration>,
    ) -> Result<T, anyhow::Error> {
        let url = self.url(path);

        let form = Form::new()
            .text("key", self.apikey.clone())
            .text("data", serde_json::to_string(&payload)?);

        let req = self.client.post(url).multipart(form);
        let req = if let Some(duration) = timeout {
            req.timeout(duration)
        } else {
            req
        };

        let resp = req.send().await?;

        match resp.error_for_status_ref() {
            Ok(_) => (),
            Err(err) => {
                if err.status() == Some(StatusCode::BAD_REQUEST) {
                    return Err(anyhow::anyhow!(resp.json::<serde_json::Value>().await?));
                } else {
                    return Err(anyhow::Error::from(err));
                };
            }
        };
        Ok(resp.json().await?)
    }
}

impl VyosApi for VyosClient {
    #[instrument(skip(self, commands, timeout))]
    async fn set_firewall_groups(
        &self,
        commands: &[VyosConfigCommand],
        timeout: Option<Duration>,
        save: bool,
    ) -> Result<(), anyhow::Error> {
        let serialized = serde_json::to_value(commands)?;
        if save {
            match serialized {
                serde_json::Value::Array(mut v) => v.push(
                    serde_json::to_value(VyosSaveCommand {
                        op: VyosSaveOperation::Save,
                    })
                    .expect("can serialize save command"),
                ),
                _ => panic!("invalid commands"),
            }
        }

        self.send::<serde_json::Value, _>("/configure", commands, timeout)
            .await?;
        Ok(())
    }
    #[instrument(skip(self))]
    async fn retrieve_firewall_network_groups<'a>(
        &self,
        group_name: &str,
    ) -> Result<VyosCommandResponse<Vec<IpNet>>, anyhow::Error> {
        let ipv4_path = format!("firewall group network-group {} network", group_name)
            .split(' ')
            .map(ToOwned::to_owned)
            .collect();
        let ipv6_path = format!("firewall group ipv6-network-group {} network", group_name)
            .split(' ')
            .map(ToOwned::to_owned)
            .collect();

        let ipv4 = self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
            "/retrieve",
            VyosGetCommand {
                op: VyosGetOperation::ReturnValues,
                path: ipv4_path,
            },
            None,
        );

        let ipv6 = self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
            "/retrieve",
            VyosGetCommand {
                op: VyosGetOperation::ReturnValues,
                path: ipv6_path,
            },
            None,
        );

        let (ipv4, ipv6) = futures_util::join!(ipv4, ipv6);
        let mut ips = ipv4?;
        ips.data.append(&mut ipv6?.data);

        Ok(ips)
    }

    fn ban_ips<'a>(
        &self,
        fw_group_name: &str,
        ips: IpSet<'a>,
    ) -> impl Future<Output = Result<serde_json::Value, anyhow::Error>> {
        let commands = ips.into_vyos_commands(VyosConfigOperation::Set, fw_group_name);

        self.send("/configure", commands, None)
    }
    fn remove_ip_ban<'a>(
        &self,
        fw_group_name: &str,
        ips: IpSet<'a>,
    ) -> impl Future<Output = Result<serde_json::Value, anyhow::Error>> {
        let commands = ips.into_vyos_commands(VyosConfigOperation::Set, fw_group_name);

        self.send("/configure", commands, None)
    }
}
