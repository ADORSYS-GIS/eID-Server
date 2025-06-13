use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    sal::transmit::config::TransmitConfig,
    server::{Server, ServerConfig},
    telemetry,
};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load().wrap_err("Failed to load configuration")?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with default configuration
    let eid_service = UseidService::new(EIDServiceConfig::default());

    let server_config = ServerConfig {
        host: &config.server.host,
        port: config.server.port,
        transmit: TransmitConfig::default(),
    };
    let server = Server::new(eid_service, server_config).await?;
    server.run().await
}
