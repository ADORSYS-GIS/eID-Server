use crate::config::Config;
use crate::session::{MemoryStore, RedisStore, SessionStore};
use crate::tls::TLS_SESSION_PREFIX;
use color_eyre::eyre::Context;
use std::sync::Arc;

pub struct SetupData {
    pub eid_store: Arc<dyn SessionStore>,
    pub tls_store: Arc<dyn SessionStore>,
}

pub async fn setup(config: &Config) -> color_eyre::Result<SetupData> {
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

    Ok(SetupData {
        eid_store,
        tls_store,
    })
}
