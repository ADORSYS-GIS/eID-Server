use eid_server::config::Config;
use eid_server::pki::master_list::schedule::{MasterListScheduler, SchedulerConfig};
use eid_server::pki::truststore::MemoryTrustStore;
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

    tracing::info!("Initializing trust store...");
    let truststore = MemoryTrustStore::new("./test_certs").await?;

    // Create scheduler with integrated trust store management
    tracing::info!("Creating master list scheduler...");
    let scheduler_config = SchedulerConfig {
        enabled: true,
        update_day: time::Weekday::Sunday,
        update_hour: 2,
        update_minute: 0,
        master_list_config: config.master_list.clone(),
    };

    let scheduler = MasterListScheduler::new(scheduler_config, truststore);

    // Perform initial master list processing
    tracing::info!("Performing initial master list processing...");
    if let Err(e) = scheduler.trigger_immediate_update().await {
        tracing::warn!("Failed to load master list: {e}. Continuing with local certificates only.")
    }

    // Start scheduler for automatic updates
    scheduler.start().await;
    tracing::info!("Master list scheduler started for automatic updates");

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
