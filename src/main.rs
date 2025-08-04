use color_eyre::eyre::Context;
use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, PskStoreAdapter, UseidService},
    server::Server,
    session::{RedisStore, SessionManager},
    telemetry,
    tls::TlsConfig,
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
    let redis_store = RedisStore::new(redis_conn);

    let session_manager = SessionManager::new(redis_store.clone());

    // Create EIDService with configuration
    let eid_service = UseidService::new(
        EIDServiceConfig {
            ecard_server_address: Some("https://localhost:3000".to_string()),
        },
        session_manager.clone(),
    );

    // build the tls configuration
    // TODO : Use real data to build the config
    let cert = include_bytes!("../Config/cert.pem");
    let key = include_bytes!("../Config/key.pem");
    let psk_store = PskStoreAdapter::new(session_manager.clone());

    // Build the TLS configuration
    let tls_config = TlsConfig::new(cert, key)
        .with_psk(psk_store)
        .with_session_store(redis_store.clone());

    let server = Server::new(redis_store, eid_service, &config, tls_config).await?;
    server.run().await
}
