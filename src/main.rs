use color_eyre::eyre::Context;
use eid_server::{
    config::{Config, TransmitConfig},
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{AppServerConfig, Server},
    telemetry,
};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load().wrap_err("Failed to load configuration")?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with configuration
    let eid_service = UseidService::new(EIDServiceConfig {
        max_sessions: 1000,
        session_timeout_minutes: 5,
        ecard_server_address: Some("https://localhost:3000".to_string()),
        redis_url: config.redis_url,
    });
    let server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port,
        transmit: TransmitConfig::default(),
        tls_cert_path: config.server.tls_cert_path,
        tls_key_path: config.server.tls_key_path,
    };
    let server = Server::new(eid_service, server_config.clone()).await?;
    server.run(server_config).await
}
