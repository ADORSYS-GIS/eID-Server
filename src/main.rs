use color_eyre::eyre::Context;
use eid_server::config::Config;
use eid_server::domain::eid::service::EidService;
use eid_server::pki::identity::{FileIdentity, Identity};
use eid_server::server::Server;
use eid_server::session::{RedisStore, SessionManager};
use eid_server::telemetry;
use eid_server::tls::{TLS_SESSION_PREFIX, TlsConfig};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    let redis_conn = config
        .redis
        .start()
        .await
        .wrap_err("Failed to start Redis")?;
    let eid_store = RedisStore::new(redis_conn.clone());
    let tls_store = RedisStore::new(redis_conn).with_prefix(TLS_SESSION_PREFIX);

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
    let identity = Identity::new(file_identity.clone(), file_identity.clone());

    let service = EidService::new(session_manager, identity);

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
