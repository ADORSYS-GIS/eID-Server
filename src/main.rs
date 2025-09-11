use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    domain::eid::service::EidService,
    server::Server,
    session::{RedisStore, SessionManager},
    telemetry,
    tls::{TestCertificates, TlsConfig, generate_test_certificates},
};

const TLS_SESSION_PREFIX: &str = "tls_session";

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

    // load server certificate and key
    // TODO : Use real data to build the config
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();

    let session_manager = SessionManager::new(eid_store);
    // Build the TLS configuration
    let tls_config = TlsConfig::new(server_cert, server_key)
        .with_psk(session_manager.clone())
        .with_session_store(tls_store);

    let service = EidService::new(session_manager)
        .wrap_err("Failed to create EID service with CSCA validation")?;

    let server = Server::new(service, &config, tls_config).await?;
    server.run().await
}
