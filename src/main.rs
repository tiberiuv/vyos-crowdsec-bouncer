use clap::Parser;
use tracing::info;
use vyos_crowdsec_bouncer::cli::Cli;
use vyos_crowdsec_bouncer::crowdsec_lapi::CrowdsecLapiClient;
use vyos_crowdsec_bouncer::main_loop::main_loop;
use vyos_crowdsec_bouncer::tracing_setup::{get_subscriber, init_subscriber};
use vyos_crowdsec_bouncer::vyos_api::VyosClient;
use vyos_crowdsec_bouncer::{App, Config};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let subscriber = get_subscriber(String::from("default"), String::from("info"));
    init_subscriber(subscriber);

    let args = Cli::parse();

    let lapi = CrowdsecLapiClient::new(
        args.crowdsec_api.clone(),
        TryFrom::try_from(args.auth.clone())?,
    );
    let vyos_api = VyosClient::new(args.vyos_api.clone(), args.vyos_apikey.clone());
    let config = Config {
        firewall_group: args.firewall_group,
        trusted_ips: args.trusted_ips.unwrap_or_default(),
        update_frequency_secs: args.update_frequency_secs,
    };
    let app = App::new(lapi, vyos_api, config);

    let _result = tokio::spawn(async { main_loop(app).await }).await?;

    info!("Exit!");

    Ok(())
}
