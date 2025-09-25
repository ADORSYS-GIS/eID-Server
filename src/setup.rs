use crate::config::Config;
use crate::domain::eid::service::EidService;
use crate::pki::identity::{FileIdentity, Identity};
use crate::pki::truststore::MemoryTrustStore;
use crate::session::{MemoryStore, RedisStore, SessionManager, SessionStore};
use crate::tls::{TLS_SESSION_PREFIX, TlsConfig};
use color_eyre::eyre::Context;
use std::sync::Arc;

pub struct SetupData {
    pub eid_store: Arc<dyn SessionStore>,
    pub tls_store: Arc<dyn SessionStore>,
}

pub async fn setup(
    config: &Config,
) -> color_eyre::Result<(EidService<MemoryTrustStore>, TlsConfig)> {
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

    Ok((
        EidService::new(session_manager, trust_store, identity),
        tls_config,
    ))
}
