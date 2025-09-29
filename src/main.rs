use eid_server::config::Config;
use eid_server::pki::master_list::MasterListHandler;
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
    let (service, tls_config) = setup(&config).await?;

    // Create scheduler with integrated trust store management
    tracing::info!("Creating master list scheduler with integrated trust store...");
    let scheduler =
        MasterListHandler::create_scheduler(&config.master_list, "./test_certs").await?;

    // Perform initial master list processing
    tracing::info!("Performing initial master list processing...");
    match scheduler.trigger_immediate_update().await {
        Ok(()) => {
            tracing::info!("Successfully loaded CSCA certificates from master list");
        }
        Err(e) => {
            tracing::warn!(
                "Failed to load master list: {e}. Continuing with local certificates only."
            );
        }
    }

    // Start scheduler for automatic updates
    let _scheduler_handle = scheduler.start().await;
    tracing::info!("Master list scheduler started for automatic updates");

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
