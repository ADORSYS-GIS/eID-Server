use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{debug, error, warn};

use crate::pki::truststore::MemoryTrustStore;

use super::errors::CrlResult;
use super::processor::CrlProcessor;

/// Configuration for CRL scheduler
#[derive(Debug, Clone)]
pub struct CrlSchedulerConfig {
    /// How often to check CRLs (in seconds)
    pub check_interval_secs: u64,
    /// CRL distribution point URLs
    pub distribution_points: Vec<String>,
    /// HTTP timeout for fetching CRLs
    pub timeout_secs: u64,
}

impl Default for CrlSchedulerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 3600, // 1 hour
            distribution_points: Vec::new(),
            timeout_secs: 30,
        }
    }
}

/// Scheduler for periodic CRL checking
pub struct CrlScheduler {
    config: CrlSchedulerConfig,
    processor: CrlProcessor,
    trust_store: MemoryTrustStore,
}

impl CrlScheduler {
    /// Create a new CRL scheduler
    pub fn new(config: CrlSchedulerConfig, trust_store: MemoryTrustStore) -> CrlResult<Self> {
        let processor = CrlProcessor::new(config.timeout_secs)?;

        Ok(Self {
            config,
            processor,
            trust_store,
        })
    }

    /// Perform immediate CRL check (for initial setup)
    pub async fn trigger_immediate_update(&self) -> CrlResult<usize> {
        debug!("Performing immediate CRL check");

        if self.config.distribution_points.is_empty() {
            warn!("No CRL distribution points configured");
            return Ok(0);
        }

        self.processor
            .process_crls(&self.config.distribution_points, &self.trust_store)
            .await
    }

    /// Start the scheduler (spawns background task)
    pub async fn start(self) -> CrlResult<()> {
        if self.config.distribution_points.is_empty() {
            debug!("No CRL distribution points configured, scheduler not started");
            return Ok(());
        }

        let check_interval = Duration::from_secs(self.config.check_interval_secs);
        debug!(
            "Starting CRL scheduler with interval of {} seconds",
            self.config.check_interval_secs
        );

        let scheduler = Arc::new(self);

        tokio::spawn(async move {
            let mut ticker = interval(check_interval);
            ticker.tick().await; // First tick completes immediately

            loop {
                ticker.tick().await;
                debug!("Running scheduled CRL check");

                match scheduler.trigger_immediate_update().await {
                    Ok(removed) => {
                        if removed > 0 {
                            debug!("Scheduled CRL check removed {} certificates", removed);
                        } else {
                            debug!("Scheduled CRL check: no revoked certificates found");
                        }
                    }
                    Err(e) => {
                        error!("Scheduled CRL check failed: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}
