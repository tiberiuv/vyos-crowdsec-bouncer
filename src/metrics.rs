use std::sync::LazyLock;

use prometheus::{
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, IntCounter, IntCounterVec, IntGaugeVec, Registry,
};

pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

pub static OUTGOING_REQUESTS_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "crowdsec_vyos_bouncer_outgoing_requests",
        "help",
        &["destination", "path"],
        &REGISTRY
    )
    .unwrap()
});

pub static VYOS_COMMANDS_SENT_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter_with_registry!("crowdsec_vyos_commands_sent", "help", &REGISTRY).unwrap()
});
pub static FIREWALL_BLOCKED_IPS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec_with_registry!(
        "crowdsec_vyos_firewall_blocked_ips",
        "help",
        &["type"],
        &REGISTRY
    )
    .unwrap()
});
