use std::sync::Arc;
use std::time::Duration;
use time::{OffsetDateTime, Time, Weekday};
use tokio::sync::Mutex;
use tokio::time::{Instant, interval, sleep_until};
use tracing::{error, info};

use crate::config::MasterListConfig;
use crate::pki::truststore::TrustStore;

/// Configuration for the master list update scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Whether the scheduler is enabled
    pub enabled: bool,
    /// Day of the week to run the update (default: Sunday)
    pub update_day: Weekday,
    /// Hour of the day to run the update (0-23, default: 2 AM)
    pub update_hour: u8,
    /// Minute of the hour to run the update (0-59, default: 0)
    pub update_minute: u8,
    /// Master list configuration
    pub master_list_config: MasterListConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_day: Weekday::Sunday,
            update_hour: 2,
            update_minute: 0,
            master_list_config: MasterListConfig::default(),
        }
    }
}

/// Scheduler for automatic master list updates
pub struct MasterListScheduler<T: TrustStore> {
    handler: Arc<super::MasterListHandler<T>>,
    config: SchedulerConfig,
    shutdown_signal: Arc<Mutex<bool>>,
}

impl<T: TrustStore + Clone + Send + Sync + 'static> MasterListScheduler<T> {
    /// Creates a new MasterListScheduler
    pub fn new(config: SchedulerConfig, truststore: T) -> Self {
        let handler = super::MasterListHandler::new(&config.master_list_config, truststore);

        Self {
            handler: Arc::new(handler),
            config,
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
    }

    /// Get a reference to the handler for external access
    pub fn handler(&self) -> Arc<super::MasterListHandler<T>> {
        Arc::clone(&self.handler)
    }

    /// Starts the scheduler in a background task
    pub async fn start(&self) -> tokio::task::JoinHandle<()> {
        if !self.config.enabled {
            info!("Master list scheduler is disabled");
            return tokio::spawn(async {});
        }

        info!(
            "Starting master list scheduler - updates every {:?} at {:02}:{:02}",
            self.config.update_day, self.config.update_hour, self.config.update_minute
        );

        let handler = Arc::clone(&self.handler);
        let config = self.config.clone();
        let shutdown_signal = Arc::clone(&self.shutdown_signal);

        tokio::spawn(async move {
            Self::run_scheduler(handler, config, shutdown_signal).await;
        })
    }

    /// Stops the scheduler
    pub async fn stop(&self) {
        info!("Stopping master list scheduler");
        *self.shutdown_signal.lock().await = true;
    }

    /// Main scheduler loop
    async fn run_scheduler(
        handler: Arc<super::MasterListHandler<T>>,
        config: SchedulerConfig,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        // Calculate initial delay to next scheduled time
        let next_run = Self::calculate_next_run_time(&config);
        info!("Next master list update scheduled for: {}", next_run);

        // Sleep until the first scheduled time
        let now = Instant::now();
        let now_utc = OffsetDateTime::now_utc();
        let duration_until_next = (next_run - now_utc).whole_seconds();

        if duration_until_next > 0 {
            sleep_until(now + Duration::from_secs(duration_until_next as u64)).await;
        }

        // Run the update immediately if we've passed the scheduled time
        Self::perform_update(&handler).await;

        // Set up weekly interval
        let mut interval = interval(Duration::from_secs(7 * 24 * 60 * 60)); // 1 week
        interval.tick().await; // Skip the first tick since we already ran

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check if we should shutdown
                    if *shutdown_signal.lock().await {
                        info!("Scheduler received shutdown signal");
                        break;
                    }

                    Self::perform_update(&handler).await;
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    // Check shutdown signal every minute
                    if *shutdown_signal.lock().await {
                        info!("Scheduler received shutdown signal");
                        break;
                    }
                }
            }
        }

        info!("Master list scheduler stopped");
    }

    /// Calculates the next run time based on the configuration
    fn calculate_next_run_time(config: &SchedulerConfig) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc();

        // Create the target time for today
        let target_time = Time::from_hms(config.update_hour, config.update_minute, 0)
            .expect("Invalid time configuration");

        let mut next_run = now.date().with_time(target_time).assume_utc();

        // Find the next occurrence of the target weekday
        while next_run.weekday() != config.update_day || next_run <= now {
            next_run = next_run.saturating_add(time::Duration::days(1));
            next_run = next_run.date().with_time(target_time).assume_utc();
        }

        next_run
    }

    /// Performs the actual master list update
    async fn perform_update(handler: &Arc<super::MasterListHandler<T>>) {
        info!("Starting scheduled master list update");

        match handler.process_master_list().await {
            Ok(count) => {
                info!(
                    "✓ Scheduled master list update completed successfully, added {count} certificates",
                );
            }
            Err(e) => {
                error!("{e}");
            }
        }
    }

    /// Triggers an immediate update (for testing or manual triggers)
    pub async fn trigger_immediate_update(&self) -> Result<(), String> {
        info!("Triggering immediate master list update");

        match self.handler.process_master_list().await {
            Ok(count) => {
                info!(
                    "✓ Immediate master list update completed successfully, added {count} certificates",
                );
                Ok(())
            }
            Err(e) => {
                error!("{e}");
                Err(e.to_string())
            }
        }
    }

    /// Verify a certificate chain using the scheduler's handler
    pub async fn verify_certificate_chain<I, D>(
        &self,
        der_chain: I,
    ) -> Result<bool, super::MasterListError>
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send,
    {
        self.handler.verify_certificate_chain(der_chain).await
    }

    /// Get a CSCA certificate by its serial number
    pub async fn get_certificate_by_serial(
        &self,
        serial_number: impl AsRef<[u8]> + Send,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, super::MasterListError> {
        self.handler.get_certificate_by_serial(serial_number).await
    }

    /// Get a CSCA certificate by its subject DN
    pub async fn get_certificate_by_subject(
        &self,
        subject: &str,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, super::MasterListError> {
        self.handler.get_certificate_by_subject(subject).await
    }

    /// Clear all certificates from the trust store
    pub async fn clear_trust_store(&self) -> Result<(), super::MasterListError> {
        self.handler.clear_trust_store().await
    }

    /// Remove expired CSCA certificates from the trust store
    pub async fn cleanup_expired_certificates(&self) -> Result<usize, super::MasterListError> {
        self.handler.cleanup_expired_certificates().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Weekday;

    #[test]
    fn test_calculate_next_run_time() {
        let config = SchedulerConfig {
            enabled: true,
            update_day: Weekday::Sunday,
            update_hour: 2,
            update_minute: 0,
            master_list_config: MasterListConfig::default(),
        };

        let next_run = MasterListScheduler::<crate::pki::truststore::MemoryTrustStore>::calculate_next_run_time(&config);

        // Verify it's a Sunday at 2:00 AM
        assert_eq!(next_run.weekday(), Weekday::Sunday);
        assert_eq!(next_run.hour(), 2);
        assert_eq!(next_run.minute(), 0);

        // Verify it's in the future
        assert!(next_run > OffsetDateTime::now_utc());
    }

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();

        assert!(config.enabled);
        assert_eq!(config.update_day, Weekday::Sunday);
        assert_eq!(config.update_hour, 2);
        assert_eq!(config.update_minute, 0);
    }
}
