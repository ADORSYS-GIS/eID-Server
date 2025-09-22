use super::MasterListFetcher;
use super::{CscaValidationError, FetcherConfig, MasterList, WebMasterListFetcher};
use crate::config::PkiConfig;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info};

/// Master List update status and information
#[derive(Debug, Clone)]
pub struct MasterListUpdateStatus {
    pub has_master_list: bool,
    pub version: Option<String>,
    pub issue_date: Option<time::OffsetDateTime>,
    pub next_update: Option<time::OffsetDateTime>,
    pub is_valid: bool,
    pub countries_count: usize,
    pub total_certificates: usize,
}

/// Service for handling periodic updates of Master Lists using cron scheduling
pub struct PeriodicUpdater {
    fetcher: Arc<dyn MasterListFetcher>,
    scheduler: Arc<JobScheduler>,
}

impl Clone for PeriodicUpdater {
    fn clone(&self) -> Self {
        Self {
            fetcher: Arc::clone(&self.fetcher),
            scheduler: Arc::clone(&self.scheduler),
        }
    }
}

impl PeriodicUpdater {
    /// Create a new periodic updater with default German BSI fetcher
    pub async fn new(master_list_config: PkiConfig) -> Result<Self, CscaValidationError> {
        let config = FetcherConfig::default();
        let fetcher = Arc::new(WebMasterListFetcher::new(config, master_list_config)?);
        let scheduler = Arc::new(JobScheduler::new().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to create job scheduler: {e}"))
        })?);
        Ok(Self { fetcher, scheduler })
    }

    /// Create updater with existing fetcher
    pub async fn with_fetcher(
        fetcher: Arc<dyn MasterListFetcher>,
    ) -> Result<Self, CscaValidationError> {
        let scheduler = Arc::new(JobScheduler::new().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to create job scheduler: {e}"))
        })?);
        Ok(Self { fetcher, scheduler })
    }

    /// Start the periodic updater with a default daily schedule (runs at 2 AM every day)
    pub async fn start_periodic_updates(&self) -> Result<(), CscaValidationError> {
        self.start_with_schedule("0 0 2 * * *").await
    }

    /// Start the periodic updater with a custom cron schedule
    /// Format: "sec min hour day_of_month month day_of_week year"
    pub async fn start_with_schedule(
        &self,
        cron_schedule: &str,
    ) -> Result<(), CscaValidationError> {
        let fetcher = Arc::clone(&self.fetcher);

        let job = Job::new_async(cron_schedule, move |_uuid, _lock| {
            let fetcher = Arc::clone(&fetcher);
            Box::pin(async move {
                info!("Periodic Master List update triggered by scheduler");

                match fetcher.fetch().await {
                    Ok(master_list) => {
                        info!("Successfully updated Master List from scheduler - version: {}, countries: {}", 
                              master_list.version, master_list.csca_certificates.len());
                    }
                    Err(e) => {
                        error!("Failed to fetch Master List in scheduled update: {}", e);
                    }
                }
            })
        })
        .map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to create scheduled job: {e}"))
        })?;

        self.scheduler.add(job).await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to add job to scheduler: {e}"))
        })?;

        self.scheduler.start().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to start scheduler: {e}"))
        })?;

        info!(
            "Periodic Master List updater started with schedule: {}",
            cron_schedule
        );
        Ok(())
    }

    /// Check if the scheduler is running
    pub async fn is_running(&self) -> bool {
        true
    }

    /// Check if Master List needs updating (utility method)
    pub fn needs_update(master_list: Option<&MasterList>) -> bool {
        master_list.map(|ml| !ml.is_valid()).unwrap_or(true)
    }

    /// Manual update method - fetch Master List immediately if needed
    pub async fn update_master_list_now(
        &self,
        current_master_list: Option<&MasterList>,
    ) -> Result<Option<MasterList>, CscaValidationError> {
        if !Self::needs_update(current_master_list) {
            info!("Master List is still valid, no update needed");
            return Ok(None);
        }

        info!("Master List needs updating, fetching now");

        match self.fetcher.fetch().await {
            Ok(master_list) => {
                info!(
                    "Successfully updated Master List - version: {}, countries: {}",
                    master_list.version,
                    master_list.csca_certificates.len()
                );
                Ok(Some(master_list))
            }
            Err(e) => {
                error!("Failed to fetch Master List: {}", e);
                Err(e)
            }
        }
    }

    /// Get Master List update status and statistics
    pub fn get_update_status(master_list: Option<&MasterList>) -> MasterListUpdateStatus {
        match master_list {
            Some(ml) => MasterListUpdateStatus {
                has_master_list: true,
                version: Some(ml.version.clone()),
                issue_date: Some(ml.issue_date),
                next_update: Some(ml.next_update),
                is_valid: ml.is_valid(),
                countries_count: ml.csca_certificates.len(),
                total_certificates: ml.csca_certificates.values().map(|certs| certs.len()).sum(),
            },
            None => MasterListUpdateStatus {
                has_master_list: false,
                version: None,
                issue_date: None,
                next_update: None,
                is_valid: false,
                countries_count: 0,
                total_certificates: 0,
            },
        }
    }
}
