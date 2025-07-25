use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::Server,
    telemetry,
    tls::{self, TlsConfig},
};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create EIDService with configuration
    let eid_service = UseidService::new(EIDServiceConfig {
        max_sessions: 1000,
        session_timeout_minutes: 5,
        ecard_server_address: Some("https://localhost:3000".to_string()),
        redis_url: config.redis_url.clone(),
    });
    let session_mgr = eid_service.session_manager.clone();

    // build the tls configuration
    // TODO : Use real data to build the config
    let tls_session_store = tls::InMemorySessionStore::new();
    let cert = include_bytes!("../Config/cert.pem");
    let key = include_bytes!("../Config/key.pem");

    // Build the TLS configuration
    let tls_config = TlsConfig::new(cert, key)
        .with_psk(session_mgr)
        .with_session_store(tls_session_store);

    let server = Server::new(eid_service, &config, tls_config).await?;
    server.run().await
}
