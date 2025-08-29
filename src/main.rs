use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    server::Server,
    session::{RedisStore, SessionManager},
    telemetry,
    tls::{TestCertificates, TlsConfig, generate_test_certificates},
};

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
    let tls_store = RedisStore::new(redis_conn.clone()).with_prefix("tls_session");

    let session_manager = SessionManager::new(eid_store);

    // build the tls configuration
    // TODO : Use real data to build the config
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();

    // Build the TLS configuration
    let tls_config = TlsConfig::new(server_cert, server_key)
        .with_psk(session_manager.clone())
        .with_session_store(tls_store);

    let server = Server::new(session_manager, &config, tls_config).await?;
    server.run().await
}
