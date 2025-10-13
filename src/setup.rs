use crate::config::Config;
use crate::domain::service::Service;
use crate::pki::crl::scheduler::{CrlScheduler, CrlSchedulerConfig};
use crate::pki::identity::{FileIdentity, Identity};
use crate::pki::master_list::schedule::{MasterListScheduler, SchedulerConfig};
use crate::pki::truststore::MemoryTrustStore;
use crate::session::{MemoryStore, RedisStore, SessionManager, SessionStore};
use crate::tls::{TLS_SESSION_PREFIX, TlsConfig};
use color_eyre::eyre::Context;
use std::sync::Arc;
use time::Duration;
use tracing::{info, warn};

pub struct SetupData {
    pub eid_store: Arc<dyn SessionStore>,
    pub tls_store: Arc<dyn SessionStore>,
}

pub async fn setup(config: &Config) -> color_eyre::Result<(Service<MemoryTrustStore>, TlsConfig)> {
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

    let session_manager = SessionManager::new(eid_store)
        .with_max_sessions(100)
        .with_expiry(Duration::minutes(5));

    // Build the TLS configuration
    let tls_config = TlsConfig::from_pem(server_cert, server_key)
        .with_psk(session_manager.clone())
        .with_session_store(tls_store);

    let file_identity = FileIdentity::new();
    let identity = Identity::new(file_identity.clone(), file_identity);

    tracing::info!("Initializing trust store...");
    let truststore = MemoryTrustStore::new("./test_certs").await?;

    let service = Service::new(session_manager, truststore.clone(), identity);

    tracing::info!("Creating master list scheduler...");
    // The cron job will rerun everyday at midnight
    let scheduler_config = SchedulerConfig::default();

    let scheduler = MasterListScheduler::new(scheduler_config, truststore.clone());

    // Perform initial master list processing
    tracing::info!("Performing initial master list processing...");
    if let Err(e) = scheduler.trigger_immediate_update().await {
        tracing::warn!("Failed to load master list: {e}. Continuing with local certificates only.")
    }

    // Start scheduler for automatic updates
    scheduler.start().await?;
    tracing::info!("Master list scheduler started for automatic updates");

    // Initialize CRL scheduler
    if config.crl.enabled {
        info!("CRL checking is enabled");

        let crl_config = CrlSchedulerConfig {
            check_interval_secs: config.crl.check_interval_secs,
            distribution_points: config.crl.distribution_points.clone(),
            timeout_secs: config.crl.timeout_secs,
        };

        let crl_scheduler = CrlScheduler::new(crl_config, truststore.clone())
            .wrap_err("Failed to create CRL scheduler")?;

        // Perform initial CRL check
        info!("Performing initial CRL check...");
        match crl_scheduler.trigger_immediate_update().await {
            Ok(count) => {
                if count > 0 {
                    info!("Removed {} revoked certificates from trust store", count);
                } else {
                    info!("No revoked certificates found in initial CRL check");
                }
            }
            Err(e) => {
                warn!(
                    "Initial CRL check failed: {}. Continuing without initial cleanup.",
                    e
                );
            }
        }

        // Start scheduled CRL checking
        crl_scheduler.start().await?;
        info!("CRL scheduler started for periodic revocation checking");
    } else {
        warn!(
            "CRL checking is DISABLED in configuration. Certificates will not be checked for revocation."
        );
    }

    Ok((service, tls_config))
}
