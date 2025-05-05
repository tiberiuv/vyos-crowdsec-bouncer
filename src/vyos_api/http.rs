use std::time::Duration;

use ipnet::IpNet;
use reqwest::multipart::Form;
use reqwest::{Client, StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use tracing::instrument;

use crate::metrics::OUTGOING_REQUESTS_COUNTER;
use crate::USER_AGENT;

use super::interface::VyosApi;
use super::types::{ipv4_group_get, ipv6_group_get, VyosCommandResponse, VyosConfigCommand};
use super::VyosSaveCommand;

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
            .user_agent(USER_AGENT)
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
            Ok(_) => Ok(resp.json().await?),
            Err(err) => {
                if err.status() == Some(StatusCode::BAD_REQUEST) {
                    Err(anyhow::anyhow!(resp.json::<serde_json::Value>().await?))
                } else {
                    Err(anyhow::Error::from(err))
                }
            }
        }
    }
}

impl VyosApi for VyosClient {
    #[instrument(skip(self, commands, timeout))]
    async fn set_firewall_groups<'a>(
        &self,
        commands: &[VyosConfigCommand<'a>],
        timeout: Option<Duration>,
    ) -> Result<(), anyhow::Error> {
        self.send::<serde_json::Value, _>("/configure", commands, timeout)
            .await?;
        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/configure"])
            .inc();
        Ok(())
    }
    #[instrument(skip(self, timeout))]
    async fn save_config(&self, timeout: Option<Duration>) -> Result<(), anyhow::Error> {
        self.send::<serde_json::Value, _>("/config-file", VyosSaveCommand::default(), timeout)
            .await?;
        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/config-file"])
            .inc();
        Ok(())
    }
    #[instrument(skip(self))]
    async fn retrieve_firewall_network_groups(
        &self,
        group_name: &str,
    ) -> Result<VyosCommandResponse<Vec<IpNet>>, anyhow::Error> {
        let ipv4 = self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
            "/retrieve",
            ipv4_group_get(group_name),
            None,
        );

        let ipv6 = self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
            "/retrieve",
            ipv6_group_get(group_name),
            None,
        );

        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/retrieve"])
            .inc_by(2);

        let (ipv4, ipv6) = futures_util::join!(ipv4, ipv6);
        let mut ips = ipv4?;
        ips.data.append(&mut ipv6?.data);

        Ok(ips)
    }
}
