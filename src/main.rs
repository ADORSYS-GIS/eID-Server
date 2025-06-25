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
    let eid_service_config = EIDServiceConfig {
        ecard_server_address: Some(format!("https://{}:{}", config.server.host, config.server.port)),
        ..EIDServiceConfig::default()
    };
    let use_id_service = UseidService::new(eid_service_config);

    let server_config = AppServerConfig {
        host: config.server.host.clone(),
        port: config.server.port,
    };
    let server = Server::new(use_id_service, server_config.clone()).await?;
    server.run(server_config).await
}
