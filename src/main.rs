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
    let SetupData {
        eid_store,
        tls_store,
    } = setup(&config).await?;

    // load server certificate and key
    // TODO : Use real data to build the config
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();

    let session_manager = SessionManager::new(eid_store);

    // Build the TLS configuration
    let tls_config = TlsConfig::from_pem(server_cert, server_key)
        .with_psk(session_manager.clone())
        .with_session_store(tls_store);

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

    // Get trust store from scheduler for service
    let trust_store_ref = scheduler.trust_store();
    let trust_store = trust_store_ref.lock().await.clone();

    let service = EidService::new(session_manager, trust_store);
    let (service, tls_config) = setup(&config).await?;

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
