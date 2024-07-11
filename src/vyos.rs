use std::net::{Ipv4Addr, Ipv6Addr};

use cidr::AnyIpCidr;
use reqwest::multipart::Form;
use reqwest::{Client, IntoUrl, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug)]
pub struct VyosClient {
    client: Client,
    host: Url,
    apikey: String,
}

pub enum VyosError {}

pub struct Response<T, E> {
    success: bool,
    data: T,
    error: E,
}

trait VyosApi {
    async fn ban_ip(
        &self,
        fw_group_name: &str,
        ip: AnyIpCidr,
    ) -> Result<Response<(), ()>, VyosError>;
    async fn remove_ip_ban(
        &self,
        fw_group_name: &str,
        ip: AnyIpCidr,
    ) -> Result<Response<(), ()>, VyosError>;
}

impl VyosClient {
    fn url(&self, path: &str) -> Url {
        self.host.join(path).expect("invalid url")
    }
    async fn send<T: DeserializeOwned, P: Serialize>(
        &self,
        path: &str,
        payload: P,
    ) -> Result<T, anyhow::Error> {
        let url = self.url(path);

        let form = Form::new()
            .text("apikey", self.apikey.clone())
            .text("data", serde_json::to_string(&payload)?);

        let resp = self.client.post(url).multipart(form).send().await?;
        let resp = resp.error_for_status()?;

        Ok(resp.json().await?)
    }
}

