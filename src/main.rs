use eid_server::config::Config;
use eid_server::server::Server;
use eid_server::setup::setup;
use eid_server::telemetry;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::debug!("Loaded configuration: {:?}", config);

    // Setup server components
    let components = setup(&config).await?;

    let server = Server::new(components.service, &config, components.tls_config).await?;
    server.run().await
}
