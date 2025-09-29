use eid_server::config::Config;
use eid_server::server::Server;
use eid_server::{setup::setup, telemetry};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::debug!("Loaded configuration: {:?}", config);

    // Setup server components
    let (service, tls_config) = setup(&config).await?;

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
