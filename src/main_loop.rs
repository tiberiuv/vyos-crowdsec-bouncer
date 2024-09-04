use std::time::Duration;
use tracing::{error, info};

use crate::blacklist::IpRangeMixed;
use crate::crowdsec_lapi::types::DecisionsIpRange;
use crate::crowdsec_lapi::{CrowdsecLAPI, DecisionsOptions, DEFAULT_DECISION_ORIGINS};
use crate::utils::retry_op;
use crate::vyos_api::{update_firewall, VyosApi};
use crate::App;

pub async fn store_existing_blacklist(app: &App) -> Result<(), anyhow::Error> {
    let existing_networks = app
        .vyos
        .retrieve_firewall_network_groups(&app.config.firewall_group)
        .await?;

    let blacklist = IpRangeMixed::from(existing_networks.data);
    app.blacklist.store(blacklist);
    Ok(())
}

pub async fn do_iteration(
    app: &App,
    trusted_ips: &IpRangeMixed,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    info!("Fetching decisions");

    let new_decisions = app.lapi.stream_decisions(decision_options).await?;

    if decision_options.get_startup() {
        store_existing_blacklist(app).await?;
    }

    let blacklist = app.blacklist.load();
    let decision_ips = DecisionsIpRange::from(new_decisions)
        .filter_new(trusted_ips)
        .filter_new(blacklist.as_ref())
        .filter_deleted(blacklist.as_ref());

    if !decision_ips.is_empty() {
        if let Err(err) = update_firewall(
            &app.vyos,
            &decision_ips,
            &app.config.firewall_group,
            Some(Duration::from_secs(60 * 5)),
        )
        .await
        {
            error!(msg = "Failed to update firewall", ?err);
        } else {
            let new_blacklist = app
                .blacklist
                .load()
                .as_ref()
                .merge(&decision_ips.new)
                .exclude(&decision_ips.deleted);
            app.blacklist.store(new_blacklist)
        };
    } else {
        info!("No new decisions to add!");
    }
    Ok(())
}

pub async fn main_loop(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let trusted_ips = IpRangeMixed::from(app.config.trusted_ips.clone());
    let mut decisions_options = DecisionsOptions::new(&DEFAULT_DECISION_ORIGINS, true);

    retry_op(5, || do_iteration(&app, &trusted_ips, &decisions_options)).await?;

    decisions_options.set_startup(false);
    loop {
        tokio::time::sleep(Duration::from_secs(app.config.update_frequency_secs)).await;

        retry_op(10, || do_iteration(&app, &trusted_ips, &decisions_options)).await?
    }
}

#[cfg(test)]
mod tests {
    use crate::blacklist::IpRangeMixed;
    use crate::crowdsec_lapi::types::{CrowdsecAuth, Decision, DecisionsResponse, Scope};
    use crate::crowdsec_lapi::{CrowdsecLapiClient, DecisionsOptions};
    use crate::vyos_api::VyosClient;
    use crate::Config;

    use super::{do_iteration, App};
    use iprange::IpRange;
    use mockito::Server;

    fn lapi_client(apikey: String, mock: &Server) -> CrowdsecLapiClient {
        let url = format!("http://{}", mock.host_with_port());
        CrowdsecLapiClient::new(url.parse().unwrap(), CrowdsecAuth::Apikey(apikey))
    }

    fn vyos_client(apikey: String, mock: &Server) -> VyosClient {
        let url = format!("http://{}", mock.host_with_port());
        VyosClient::new(url.parse().unwrap(), apikey)
    }

    fn mock_decision(value: &str) -> Decision {
        let scope = if value.contains('/') {
            Scope::Range
        } else {
            Scope::Ip
        };
        Decision {
            value: String::from(value),
            scope,
            ..Default::default()
        }
    }
    fn mock_decisions<'a>(
        cidrs_new: impl IntoIterator<Item = &'a str>,
        cidrs_delete: impl IntoIterator<Item = &'a str>,
    ) -> DecisionsResponse {
        DecisionsResponse {
            new: Some(cidrs_new.into_iter().map(mock_decision).collect()),
            deleted: Some(cidrs_delete.into_iter().map(mock_decision).collect()),
        }
    }

    #[tokio::test]
    async fn iteration_sucessful() {
        let mut lapi = Server::new_async().await;
        let mut vyos = Server::new_async().await;
        let apikey = String::from("test_key");
        let app = App {
            lapi: lapi_client(apikey.clone(), &lapi),
            vyos: vyos_client(apikey.clone(), &vyos),
            config: Config {
                firewall_group: String::from("group"),
                trusted_ips: vec![],
                update_frequency_secs: 1,
            },
            blacklist: crate::blacklist::BlacklistCache::new(IpRangeMixed::default()),
        };

        let add_ips = ["127.0.0.1/32", "127.0.0.2", "junk"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = lapi
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("apikey", "test_key")
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve = vyos
            .mock("POST", "/retrieve")
            .with_body("{\"success\": true, \"data\": []}")
            .with_status(200)
            .expect(2)
            .create();

        let config = vyos
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .create();

        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };
        let result = do_iteration(&app, &IpRangeMixed::default(), &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve.assert();
        config.assert();
        assert_eq!(
            app.blacklist.load().v4,
            IpRange::from_iter(
                ["127.0.0.1/32", "127.0.0.2/32"]
                    .into_iter()
                    .map(|x| x.parse().unwrap())
            )
        );

        let next_decisions = mock_decisions(["127.0.0.3"], ["127.0.0.1"]);

        let lapi_stream = lapi
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("apikey", "test_key")
            .with_body(serde_json::to_vec(&next_decisions).expect("valid json"))
            .with_status(200)
            .create();

        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };
        let config = vyos
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .create();
        let result = do_iteration(&app, &IpRangeMixed::default(), &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();
        assert_eq!(
            app.blacklist.load().v4,
            IpRange::from_iter(
                ["127.0.0.2/32", "127.0.0.3/32"]
                    .into_iter()
                    .map(|x| x.parse().unwrap())
            )
        );
    }
}
