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

pub async fn reconcile_decisions(
    app: &App,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    info!("Fetching decisions");

    let new_decisions = app.lapi.stream_decisions(decision_options).await?;

    if decision_options.get_startup() {
        store_existing_blacklist(app).await?;
    }

    let blacklist = app.blacklist.load();
    let decision_ips = DecisionsIpRange::from(new_decisions)
        .filter_new(&app.config.trusted_ips)
        .filter_new(blacklist.as_ref())
        .filter_deleted(blacklist.as_ref());

    if !decision_ips.is_empty() {
        if let Err(err) = update_firewall(
            &app.vyos,
            &decision_ips,
            &app.config.firewall_group,
            Some(std::time::Duration::from_secs(60 * 5)),
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

pub async fn reconcile(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let mut decisions_options = DecisionsOptions::new(&DEFAULT_DECISION_ORIGINS, true);
    let mut start = std::time::Instant::now();
    loop {
        if start.elapsed() > app.config.full_update_period {
            decisions_options.set_startup(true);
            start = std::time::Instant::now();
        }

        retry_op(10, || reconcile_decisions(&app, &decisions_options)).await?;

        tokio::time::sleep(app.config.update_period).await;
        if decisions_options.get_startup() {
            decisions_options.set_startup(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blacklist::IpRangeMixed;
    use crate::crowdsec_lapi::types::{CrowdsecAuth, Decision, DecisionsResponse, Scope};
    use crate::crowdsec_lapi::{CrowdsecLapiClient, DecisionsOptions};
    use crate::vyos_api::{VyosClient, VyosCommandResponse};
    use crate::Config;

    use super::{reconcile_decisions, App};
    use iprange::IpRange;
    use mockito::{Mock, Server, ServerGuard};

    fn lapi_client(apikey: String, mock: &Server) -> CrowdsecLapiClient {
        let url = format!("http://{}", mock.host_with_port());
        CrowdsecLapiClient::new(
            url.parse().unwrap(),
            CrowdsecAuth::Apikey(apikey),
            std::time::Duration::from_secs(1),
        )
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
    fn mock_save_command(mock: &mut ServerGuard) -> Mock {
        mock.mock("POST", "/config-file")
            .with_body("{\"success\": true, \"data\": []}")
            .with_status(200)
            .expect(1)
            .create()
    }
    struct TestApp {
        app: App,
        lapi_mock: ServerGuard,
        vyos_mock: ServerGuard,
    }
    async fn mock_app(apikey: &str) -> TestApp {
        let lapi_mock = Server::new_async().await;
        let vyos_mock = Server::new_async().await;
        let app = App {
            lapi: lapi_client(apikey.to_string(), &lapi_mock),
            vyos: vyos_client(apikey.to_string(), &vyos_mock),
            config: Config {
                firewall_group: String::from("group"),
                trusted_ips: IpRangeMixed::default(),
                update_period: std::time::Duration::from_secs(1),
                full_update_period: std::time::Duration::from_secs(5),
            },
            blacklist: crate::BlacklistCache::default(),
        };

        TestApp {
            app,
            lapi_mock,
            vyos_mock,
        }
    }

    #[tokio::test]
    async fn iteration_sucessful() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let add_ips = ["127.0.0.1/32", "127.0.0.2", "junk"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("apikey", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .with_body(
                serde_json::to_string(&VyosCommandResponse {
                    success: true,
                    data: Vec::<()>::new(),
                    error: None,
                })
                .unwrap(),
            )
            .with_status(200)
            .expect(2)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);

        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };
        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(
                ["127.0.0.1/32", "127.0.0.2/32"]
                    .into_iter()
                    .map(|x| x.parse().unwrap())
            )
        );

        let next_decisions = mock_decisions(["127.0.0.3"], ["127.0.0.1"]);

        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("apikey", apikey)
            .with_body(serde_json::to_vec(&next_decisions).expect("valid json"))
            .with_status(200)
            .create();

        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);
        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4.clone(),
            IpRange::from_iter(["127.0.0.2/31"].into_iter().map(|x| x.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn no_update_if_present_in_cache() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let add_ips = ["127.0.0.1/32"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("apikey", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .with_body(
                serde_json::to_string(&VyosCommandResponse {
                    success: true,
                    data: add_ips,
                    error: None,
                })
                .unwrap(),
            )
            .with_status(200)
            .expect(2)
            .create();

        // No call to update firewall since all the decisions already exist
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .expect(0)
            .create();
        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve.assert();
        config.assert();
    }

    #[tokio::test]
    async fn no_update_for_whitelisted_nets() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;
        test_app.app.config.trusted_ips = vec!["127.0.0.1/32".parse().unwrap()].into();

        let add_ips = ["127.0.0.1/32"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("apikey", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();

        // No call to update firewall since the subnet is whitelisted
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body("{}")
            .with_status(200)
            .expect(0)
            .create();
        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();
    }
}
