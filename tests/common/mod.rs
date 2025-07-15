use eid_server::{
    config::{Config, TransmitConfig},
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{AppServerConfig, Server},
};
use std::env;

pub async fn spawn_server() -> String {
    // Get project root directory
    let base_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        // Fixed paths - added "/tests/tls/" directory
        config.server.tls_cert_path = format!("{base_dir}/Config/cert.pem");
        config.server.tls_key_path = format!("{base_dir}/Config/key.pem");
        config
    };
    let eid_service = UseidService::new(EIDServiceConfig::default());

    let server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port,
        transmit: TransmitConfig::default(),
        tls_cert_path: config.server.tls_cert_path,
        tls_key_path: config.server.tls_key_path,
    };

    let server = Server::new(eid_service, server_config.clone())
        .await
        .unwrap();

    let (port, handle) = server.run_with_port(server_config.clone()).await.unwrap();
    tokio::spawn(handle);

    format!("https://{}:{}", server_config.host, port)
}
