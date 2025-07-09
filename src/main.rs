use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    psk_tls_server::create_test_tls_config,
    server::{Server, ServerConfig},
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

    // Create config directory if it doesn't exist
    let config_dir = std::path::Path::new("config");
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)?;
        println!("Created config directory");
    }

    // Create ServerConfig with references to config values
    let server_config = ServerConfig {
        host: &config.server.host, // Use reference instead of owned value
        port: config.server.port,
        tls_enabled: true,
    };

    // if !config.tls.psk_identity.is_empty() {
    // Use TLS configuration if PSK identity is provided
    // Create test TLS configuration with self-signed certificate
    let tls_psk_config = create_test_tls_config()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create TLS config: {}", e))?;

    let server = Server::new_with_tls(eid_service, server_config, Some(tls_psk_config)).await?;
    server.run().await
    // } else {
    //     // Use regular HTTP server
    //     let server = Server::new(eid_service, server_config).await?;
    //     server.run().await
    // }
}
