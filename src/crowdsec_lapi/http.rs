use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{info, instrument};

use super::types::{CrowdsecAuth, DecisionsResponse, Origin};
use crate::crowdsec_lapi::interface::CrowdsecLAPI;
use crate::metrics::OUTGOING_REQUESTS_COUNTER;
use crate::USER_AGENT;

#[derive(Debug)]
pub struct CrowdsecLapiClient {
    client: Client,
    host: Url,
}

impl CrowdsecLapiClient {
    pub fn new(host: Url, auth: CrowdsecAuth) -> Self {
        let builder = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .user_agent(USER_AGENT);
        let client = match auth.clone() {
            CrowdsecAuth::Apikey(apikey) => {
                let mut headers_map = HeaderMap::new();
                headers_map.insert(
                    "apikey",
                    HeaderValue::from_str(&apikey).expect("invalid key"),
                );

                builder.default_headers(headers_map).build()
            }
            CrowdsecAuth::Certs(ref cert_auth) => builder
                .use_rustls_tls()
                .add_root_certificate(cert_auth.root_ca.clone())
                .identity(cert_auth.identity.clone())
                .build(),
        }
        .expect("Failed to build client");
        Self { client, host }
    }

    pub fn new_with_client(host: Url, client: Client) -> Self {
        Self { client, host }
    }

    fn url(&self, path: &str) -> Url {
        self.host.join(path).expect("invalid url")
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        f: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<T, anyhow::Error> {
        let url = self.url(path);

        let request = self.client.get(url);

        let resp = f(request).send().await?.error_for_status()?;

        Ok(resp.json().await?)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum DecisionType {
    Ban,
    Captcha,
}

#[derive(Serialize, Default, Debug)]
pub struct DecisionsOptions {
    pub startup: bool,
    #[serde(rename = "type")]
    pub type_: Option<DecisionType>,
    pub origins: Option<String>,
    pub dedup: Option<bool>,
}

impl DecisionsOptions {
    pub fn new(origins: &[Origin], startup: bool) -> Self {
        let origins = origins
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<String>>()
            .join(",");
        Self {
            startup,
            type_: Some(DecisionType::Ban),
            origins: Some(origins),
            // TODO: set this back to true
            // without this central decisions shadow local ones
            // and until vyos fixes the bug to allow more than
            // 15k ips we can't use central api
            dedup: Some(false),
        }
    }

    pub fn set_startup(&mut self, startup: bool) {
        self.startup = startup;
    }

    pub fn get_startup(&self) -> bool {
        self.startup
    }
}

pub const DEFAULT_DECISION_ORIGINS: [Origin; 3] = [Origin::Crowdsec, Origin::Lists, Origin::Cscli];
impl CrowdsecLAPI for CrowdsecLapiClient {
    #[instrument(skip(self, decision_options))]
    async fn stream_decisions(
        &self,
        decision_options: &DecisionsOptions,
    ) -> Result<DecisionsResponse, anyhow::Error> {
        let path = "/v1/decisions/stream";

        let resp = self
            .get::<DecisionsResponse>(path, |builder| builder.query(&decision_options))
            .await?;
        let added = resp.new.as_ref().map(Vec::len).unwrap_or_default();
        let deleted = resp.deleted.as_ref().map(Vec::len).unwrap_or_default();
        info!(
            msg = "Retrieved decisions",
            added, deleted, decision_options.startup
        );

        OUTGOING_REQUESTS_COUNTER
            .with(&HashMap::from([
                ("destination", "CROWDSEC"),
                ("path", path),
            ]))
            .inc();

        Ok(resp)
    }
}
