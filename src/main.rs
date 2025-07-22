use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::Server,
    telemetry,
    tls::TlsConfig,
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
        redis_url: config.redis_url.clone(),
    });

    // build the tls configuration
    // TODO : Use real certificates to build the config
    let tls_config = TlsConfig::new([], []);

    let server = Server::new(eid_service, &config, tls_config).await?;
    server.run().await
}
