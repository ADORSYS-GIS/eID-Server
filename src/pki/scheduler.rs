use chrono::{DateTime, Datelike, Utc, Weekday};
use log::{error, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{Instant, interval, sleep_until};

use crate::pki::trust_store::TrustStore;

/// Configuration for the master list update scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Whether the scheduler is enabled
    pub enabled: bool,
    /// Day of the week to run the update (default: Sunday)
    pub update_day: Weekday,
    /// Hour of the day to run the update (0-23, default: 2 AM)
    pub update_hour: u32,
    /// Minute of the hour to run the update (0-59, default: 0)
    pub update_minute: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_day: Weekday::Sun,
            update_hour: 2,
            update_minute: 0,
        }
    }
}

/// Scheduler for automatic master list updates
pub struct MasterListScheduler {
    trust_store: Arc<Mutex<TrustStore>>,
    config: SchedulerConfig,
    shutdown_signal: Arc<Mutex<bool>>,
}

impl MasterListScheduler {
    /// Creates a new MasterListScheduler
    pub fn new(trust_store: Arc<Mutex<TrustStore>>, config: SchedulerConfig) -> Self {
        Self {
            trust_store,
            config,
            shutdown_signal: Arc::new(Mutex::new(false)),
        }
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

        let trust_store = Arc::clone(&self.trust_store);
        let config = self.config.clone();
        let shutdown_signal = Arc::clone(&self.shutdown_signal);

        tokio::spawn(async move {
            Self::run_scheduler(trust_store, config, shutdown_signal).await;
        })
    }

    /// Stops the scheduler
    pub async fn stop(&self) {
        info!("Stopping master list scheduler");
        *self.shutdown_signal.lock().await = true;
    }

    /// Main scheduler loop
    async fn run_scheduler(
        trust_store: Arc<Mutex<TrustStore>>,
        config: SchedulerConfig,
        shutdown_signal: Arc<Mutex<bool>>,
    ) {
        // Calculate initial delay to next scheduled time
        let next_run = Self::calculate_next_run_time(&config);
        info!("Next master list update scheduled for: {}", next_run);

        // Sleep until the first scheduled time
        let now = Instant::now();
        let duration_until_next =
            (next_run.timestamp() as u64).saturating_sub(Utc::now().timestamp() as u64);

        if duration_until_next > 0 {
            sleep_until(now + Duration::from_secs(duration_until_next)).await;
        }

        // Run the update immediately if we've passed the scheduled time
        Self::perform_update(&trust_store).await;

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

                    Self::perform_update(&trust_store).await;
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
    fn calculate_next_run_time(config: &SchedulerConfig) -> DateTime<Utc> {
        let now = Utc::now();
        let mut next_run = now
            .date_naive()
            .and_hms_opt(config.update_hour, config.update_minute, 0)
            .unwrap()
            .and_utc();

        // Find the next occurrence of the target weekday
        while next_run.weekday() != config.update_day || next_run <= now {
            next_run += chrono::Duration::days(1);
            next_run = next_run
                .date_naive()
                .and_hms_opt(config.update_hour, config.update_minute, 0)
                .unwrap()
                .and_utc();
        }

        next_run
    }

    /// Performs the actual master list update
    async fn perform_update(trust_store: &Arc<Mutex<TrustStore>>) {
        info!("Starting scheduled master list update");

        match trust_store.lock().await.update_from_master_list().await {
            Ok(()) => {
                info!("✓ Scheduled master list update completed successfully");
            }
            Err(e) => {
                error!("✗ Scheduled master list update failed: {}", e);
                // Log but don't panic - we'll try again next week
            }
        }
    }

    /// Triggers an immediate update (for testing or manual triggers)
    pub async fn trigger_immediate_update(&self) -> Result<(), String> {
        info!("Triggering immediate master list update");

        match self
            .trust_store
            .lock()
            .await
            .update_from_master_list()
            .await
        {
            Ok(()) => {
                info!("✓ Immediate master list update completed successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("✗ Immediate master list update failed: {}", e);
                error!("{}", error_msg);
                Err(error_msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Timelike, Weekday};

    #[test]
    fn test_calculate_next_run_time() {
        let config = SchedulerConfig {
            enabled: true,
            update_day: Weekday::Sun,
            update_hour: 2,
            update_minute: 0,
        };

        let next_run = MasterListScheduler::calculate_next_run_time(&config);

        // Verify it's a Sunday at 2:00 AM
        assert_eq!(next_run.weekday(), Weekday::Sun);
        assert_eq!(next_run.hour(), 2);
        assert_eq!(next_run.minute(), 0);

        // Verify it's in the future
        assert!(next_run > Utc::now());
    }

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();

        assert!(config.enabled);
        assert_eq!(config.update_day, Weekday::Sun);
        assert_eq!(config.update_hour, 2);
        assert_eq!(config.update_minute, 0);
    }
}
