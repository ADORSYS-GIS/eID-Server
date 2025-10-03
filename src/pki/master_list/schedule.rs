use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, error};

use crate::config::MasterListConfig;
use crate::pki::master_list::MasterListError;
use crate::pki::truststore::TrustStore;

/// Configuration for the master list update scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Whether the scheduler is enabled
    pub enabled: bool,
    /// Cron expression for scheduling updates (e.g., "0 0 0 * * *" for daily at 00 AM)
    pub cron_expression: String,
    /// Master list configuration
    pub master_list_config: MasterListConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cron_expression: "0 0 0 * * *".to_string(), // Daily at 00:00 am
            master_list_config: MasterListConfig::default(),
        }
    }
}

/// Scheduler for automatic master list updates
pub struct MasterListScheduler<T: TrustStore> {
    handler: Arc<super::MasterListHandler<T>>,
    config: SchedulerConfig,
    scheduler: Arc<Mutex<Option<JobScheduler>>>,
}

impl<T: TrustStore + Clone + Send + Sync + 'static> MasterListScheduler<T> {
    /// Creates a new MasterListScheduler
    pub fn new(config: SchedulerConfig, truststore: T) -> Self {
        let handler = super::MasterListHandler::new(&config.master_list_config, truststore);

        Self {
            handler: Arc::new(handler),
            config,
            scheduler: Arc::new(Mutex::new(None)),
        }
    }

    /// Get a reference to the handler for external access
    pub fn handler(&self) -> Arc<super::MasterListHandler<T>> {
        Arc::clone(&self.handler)
    }

    /// Starts the scheduler in a background task
    pub async fn start(&self) -> Result<(), MasterListError> {
        if !self.config.enabled {
            debug!("Master list scheduler is disabled");
            return Ok(());
        }

        debug!(
            "Starting master list scheduler with cron expression: {}",
            self.config.cron_expression
        );

        let job_scheduler = JobScheduler::new().await?;

        let handler = Arc::clone(&self.handler);
        let cron_expr = self.config.cron_expression.clone();

        // Create the cron job
        let job = Job::new_async(cron_expr.as_str(), move |_uuid, _lock| {
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                Self::perform_update(&handler).await;
            })
        })?;

        job_scheduler.add(job).await?;
        job_scheduler.start().await?;

        // Store the scheduler
        *self.scheduler.lock().await = Some(job_scheduler);

        debug!("Master list scheduler started successfully");
        Ok(())
    }

    /// Stops the scheduler
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Stopping master list scheduler");

        let mut scheduler_lock = self.scheduler.lock().await;
        if let Some(mut scheduler) = scheduler_lock.take() {
            scheduler.shutdown().await?;
            debug!("Master list scheduler stopped");
        }

        Ok(())
    }

    /// Performs the actual master list update
    async fn perform_update(handler: &Arc<super::MasterListHandler<T>>) {
        debug!("Starting scheduled master list update");

        match handler.process_master_list().await {
            Ok(count) => {
                debug!(
                    "✓ Scheduled master list update completed successfully, added {count} certificates",
                );
            }
            Err(e) => {
                error!("Scheduled master list update failed: {e}");
            }
        }
    }

    /// Triggers an immediate update (for testing or manual triggers)
    pub async fn trigger_immediate_update(&self) -> Result<(), String> {
        debug!("Triggering immediate master list update");

        match self.handler.process_master_list().await {
            Ok(count) => {
                debug!(
                    "✓ Immediate master list update completed successfully, added {count} certificates",
                );
                Ok(())
            }
            Err(e) => {
                error!("Immediate master list update failed: {e}");
                Err(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();

        assert!(config.enabled);
        assert_eq!(config.cron_expression, "0 0 2 * * *");
    }

    #[test]
    fn test_custom_cron_expression() {
        let config = SchedulerConfig {
            enabled: true,
            cron_expression: "0 0 */6 * * *".to_string(), // Every 6 hours
            master_list_config: MasterListConfig::default(),
        };

        assert_eq!(config.cron_expression, "0 0 */6 * * *");
    }
}
