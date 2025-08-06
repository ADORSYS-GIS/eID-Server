use color_eyre::eyre::{Context, Result};
use eid_server::{
    config::{Config},
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{AppServerConfig, Server},
    telemetry,
    tls::{self, TlsConfig},
};
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
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
        redis_url: config.redis_url.clone(),
    });
    let session_mgr = eid_service.session_manager.clone();

    // Build the TLS configuration
    let cert = fs::read(&config.server.tls_cert_path).wrap_err(format!(
        "Failed to read TLS certificate from {}",
        config.server.tls_cert_path
    ))?;
    let key = fs::read(&config.server.tls_key_path).wrap_err(format!(
        "Failed to read TLS key from {}",
        config.server.tls_key_path
    ))?;
    let tls_session_store = tls::InMemorySessionStore::new();
    let tls_config = TlsConfig::new(
        <&[u8] as Into<Vec<u8>>>::into(&*cert),
        <&[u8] as Into<Vec<u8>>>::into(&*key),
    )
    .with_psk(session_mgr)
    .with_session_store(tls_session_store);

    // Convert ServerConfig to AppServerConfig
    let app_server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port,
        tls_cert_path: config.server.tls_cert_path,
        tls_key_path: config.server.tls_key_path,
        transmit: config.server.transmit,
    };

    // Create and run the server
    let server = Server::new(eid_service, app_server_config, tls_config)
        .await
        .wrap_err("Failed to initialize server")?;
    server.run().await.wrap_err("Server failed to run")
}
