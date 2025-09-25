use eid_server::config::Config;
use eid_server::domain::eid::service::EidService;
use eid_server::pki::identity::{FileIdentity, Identity};
use eid_server::pki::truststore::MemoryTrustStore;
use eid_server::server::Server;
use eid_server::session::SessionManager;
use eid_server::tls::TlsConfig;
use eid_server::{
    setup::{SetupData, setup},
    telemetry,
};

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

    // load server certificate chain and key
    // TODO : Use real data to build the config
    let server_cert = include_bytes!("../test_certs/identity/server_chain.pem");
    let server_key = include_bytes!("../test_certs/identity/server.key");

    let session_manager = SessionManager::new(eid_store);

    // Build the TLS configuration
    let tls_config = TlsConfig::from_pem(server_cert, server_key)
        .with_psk(session_manager.clone())
        .with_session_store(tls_store);

    let file_identity = FileIdentity::new();
    let identity = Identity::new(file_identity.clone(), file_identity);
    let trust_store = MemoryTrustStore::new("./test_certs").await?;

    let service = EidService::new(session_manager, trust_store, identity);
    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
