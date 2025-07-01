use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{Server, ServerConfig},
    telemetry,
};

// Use the psk_tls_server module from the library
use eid_server::psk_tls_server;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with default configuration
    let eid_service = UseidService::new(EIDServiceConfig::default());

    let server_config = ServerConfig {
        host: &config.server.host,
        port: config.server.port,
    };

    // Create config directory if it doesn't exist
    let config_dir = std::path::Path::new("config");
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)?;
        println!("Created config directory");
    }

    // For demonstration, use PSK server if psk_identity is set (customize as needed)
    if !config.tls.psk_identity.is_empty() {
        psk_tls_server::run_psk_tls_server(&config, eid_service).await?;
        Ok(())
    } else {
        let server = Server::new(eid_service, server_config, Some(config.tls)).await?;
        server.run().await
    }
}
