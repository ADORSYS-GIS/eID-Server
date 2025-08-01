use color_eyre::eyre::{Context, Result};
use eid_server::{
    config::{Config, TransmitConfig},
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::Server,
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
    let cert = fs::read(&config.server.tls_cert_path)
        .wrap_err(format!("Failed to read TLS certificate from {}", config.server.tls_cert_path))?;
    let key = fs::read(&config.server.tls_key_path)
        .wrap_err(format!("Failed to read TLS key from {}", config.server.tls_key_path))?;
    let tls_session_store = tls::InMemorySessionStore::new();
    let tls_config = TlsConfig::new(&cert, &key)
        .with_psk(session_mgr)
        .with_session_store(tls_session_store)
        .with_min_tls_version(&config.server.transmit.min_tls_version)
        .with_cipher_suites(&config.server.transmit.allowed_cipher_suites)
        .with_client_cert_required(config.server.transmit.require_client_certificate);

    // Create and run the server
    let server = Server::new(
        eid_service,
        &config,
        tls_config,
    )
    .await
    .wrap_err("Failed to initialize server")?;
    server.run().await.wrap_err("Server failed to run")
}