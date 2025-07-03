use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{AppServerConfig, Server},
    telemetry,
};
use rustls::crypto::ring::default_provider;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Initialize the default CryptoProvider before any Rustls operations
    default_provider()
        .install_default()
        .map_err(|_| color_eyre::eyre::eyre!("Failed to install CryptoProvider"))?;

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:#?}", config);

    // Create EIDService
    let use_id_service = UseidService::new(EIDServiceConfig::default());

    // Configure server with certificate paths
    let server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port,
        cert_path: Some("certss/localhost.crt".to_string()),
        key_path: Some("certss/localhost.key".to_string()),
        psk_enabled: true,
    };

    tracing::debug!(
        "Using TLS cert: {}",
        server_config.cert_path.as_deref().unwrap_or("none")
    );
    tracing::debug!(
        "Using TLS key: {}",
        server_config.key_path.as_deref().unwrap_or("none")
    );

    let server = Server::new(use_id_service, server_config.clone()).await?;
    server.run(server_config).await
}
