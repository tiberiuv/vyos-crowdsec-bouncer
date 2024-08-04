use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{info, instrument};

use super::types::{CrowdsecAuth, DecisionsResponse, Origin};
use crate::crowdsec_lapi::interface::CrowdsecLAPI;

#[derive(Debug)]
pub struct CrowdsecLapiClient {
    client: Client,
    host: Url,
    auth: CrowdsecAuth,
}

impl CrowdsecLapiClient {
    pub fn new(host: Url, auth: CrowdsecAuth) -> Self {
        let client = match auth.clone() {
            CrowdsecAuth::Apikey(apikey) => {
                let mut headers_map = HeaderMap::new();
                headers_map.insert(
                    "apikey",
                    HeaderValue::from_str(&apikey).expect("invalid key"),
                );

                Client::builder()
                    .timeout(Duration::from_secs(5))
                    .connect_timeout(Duration::from_secs(2))
                    .default_headers(headers_map)
                    .build()
            }
            CrowdsecAuth::Certs(ref cert_auth) => Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(2))
                .add_root_certificate(cert_auth.root_ca.clone())
                .identity(cert_auth.identity.clone())
                .build(),
        }
        .expect("Failed to build client");

        Self { host, client, auth }
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

        let mut request = self.client.get(url);

        if let CrowdsecAuth::Apikey(ref apikey) = self.auth {
            request = request.header("apikey", apikey);
        }
        let resp = f(request).send().await?;

        let resp = resp.error_for_status()?;

        Ok(resp.json().await?)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
enum DecisionType {
    Ban,
    Captcha,
}

#[derive(Serialize, Default)]
pub struct DecisionsOptions {
    startup: Option<bool>,
    #[serde(rename = "type")]
    type_: Option<DecisionType>,
    origins: Option<String>,
}

impl CrowdsecLAPI for CrowdsecLapiClient {
    #[instrument(skip(self))]
    async fn stream_decisions(
        &self,
        pull_history: bool,
    ) -> Result<DecisionsResponse, anyhow::Error> {
        let path = "/v1/decisions/stream";

        let resp = self
            .get::<DecisionsResponse>(path, |builder| {
                let opts = DecisionsOptions {
                    startup: Some(true),
                    type_: Some(DecisionType::Ban),
                    origins: Some(
                        [Origin::Crowdsec, Origin::Lists]
                            .map(|o| o.to_string())
                            .join(","),
                    ),
                };
                builder.query(&opts)
            })
            .await?;
        let added = resp.new.as_ref().map(Vec::len).unwrap_or_default();
        let deleted = resp.deleted.as_ref().map(Vec::len).unwrap_or_default();
        info!(msg = "Retrieved decisions", added, deleted, pull_history);

        Ok(resp)
    }
}
