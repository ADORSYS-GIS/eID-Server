use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::Server,
    telemetry,
    tls::TlsConfig,
};

use std::fs;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with configuration
    let eid_service = UseidService::new(EIDServiceConfig {
        max_sessions: 1000,
        session_timeout_minutes: 5,
        ecard_server_address: Some("https://localhost:3000".to_string()),
        redis_url: config.redis_url.clone(),
    });

    // Load certificate and key files from Config/ directory
    let cert = fs::read("Config/cert.pem").wrap_err("Failed to read Config/cert.pem")?;
    let key = fs::read("Config/key.pem").wrap_err("Failed to read Config/key.pem")?;

    // Build the TLS configuration
    let tls_config = TlsConfig::new(&*cert, &*key);

    let server = Server::new(eid_service, &config, tls_config).await?;
    server.run().await
}
