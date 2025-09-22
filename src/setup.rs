use crate::config::Config;
use crate::domain::eid::service::EidService;
use crate::session::{MemoryStore, RedisStore, SessionManager, SessionStore};
use crate::tls::{TLS_SESSION_PREFIX, TestCertificates, TlsConfig, generate_test_certificates};
use color_eyre::eyre::Context;
use std::sync::Arc;

pub async fn setup(config: &Config) -> color_eyre::Result<(EidService, TlsConfig)> {
    let (eid_store, tls_store): (Arc<dyn SessionStore>, Arc<dyn SessionStore>) =
        if let Some(redis_config) = &config.redis {
            tracing::info!("Redis URI provided, using Redis for session storage.");
            let redis_conn = redis_config
                .start()
                .await
                .wrap_err("Failed to start Redis")?;

            let eid_s = RedisStore::new(redis_conn.clone());
            let tls_s = RedisStore::new(redis_conn).with_prefix(TLS_SESSION_PREFIX);
            (Arc::new(eid_s), Arc::new(tls_s))
        } else {
            tracing::info!("No Redis URI, using in-memory session storage.");
            (Arc::new(MemoryStore::new()), Arc::new(MemoryStore::new()))
        };

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

    let service = EidService::new(session_manager);
    Ok((service, tls_config))
}
