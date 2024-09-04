use crate::metrics::REGISTRY;
use axum::http::Response;
use axum::routing::method_routing;
use axum::Router;
use axum_server::Server;
use prometheus::Encoder;
use std::net::SocketAddr;

async fn prometheus_metrics() -> axum::response::Response {
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);
    Response::new(res.into())
}

pub struct Prometheus {
    server: Server,
}

impl Prometheus {
    pub fn new(addr: SocketAddr) -> Self {
        let server = axum_server::bind(addr);

        Self { server }
    }

    pub async fn serve(self) -> std::io::Result<()> {
        let router = Router::new()
            .route("/metrics", method_routing::get(prometheus_metrics))
            .into_make_service();
        self.server.serve(router).await
    }
}
