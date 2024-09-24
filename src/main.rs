use clap::Parser;
use tracing::info;
use vyos_crowdsec_bouncer::cli::Cli;
use vyos_crowdsec_bouncer::control_loop::reconcile;
use vyos_crowdsec_bouncer::crowdsec_lapi::CrowdsecLapiClient;
use vyos_crowdsec_bouncer::prometheus::Prometheus;
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
        std::time::Duration::from_secs(args.crowdsec_timeout),
    );
    let vyos_api = VyosClient::new(args.vyos_api.clone(), args.vyos_apikey.clone());
    let config = Config {
        firewall_group: args.firewall_group,
        trusted_ips: args.trusted_ips.map(From::from).unwrap_or_default(),
        update_period: std::time::Duration::from_secs(args.update_period_secs),
    };
    let app = App::new(lapi, vyos_api, config);
    let metrics = Prometheus::new("127.0.0.1:3000".parse().unwrap());
    let metrics = metrics.serve();

    let mut task_set = tokio::task::JoinSet::new();
    task_set.spawn(async { reconcile(app).await });
    task_set.spawn(async { Ok(metrics.await?) });

    while let Some(res) = task_set.join_next().await {
        res??;
    }

    info!("Exit!");

    Ok(())
}
