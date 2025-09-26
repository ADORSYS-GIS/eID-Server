use eid_server::config::Config;
use eid_server::domain::service::EidService;
use eid_server::pki::truststore::MemoryTrustStore;
use eid_server::server::Server;
use eid_server::session::SessionManager;
use eid_server::setup::SetupData;
use eid_server::tls::{TestCertificates, TlsConfig, generate_test_certificates};
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

    let trust_store = MemoryTrustStore::new("./test_certs").await?;

    let service = EidService::new(session_manager, trust_store);

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
