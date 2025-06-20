use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{Server, AppServerConfig},
    telemetry,
};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with default configuration
    let eid_service = UseidService::new(EIDServiceConfig::default());
    let server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port, // Uses port 3000 from config
    };
    let server = Server::new(eid_service, server_config.clone()).await?;
    server.run(server_config).await
}
