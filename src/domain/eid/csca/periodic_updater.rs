use super::{CscaValidationError, MasterList, MasterListFetcher};
use std::time::Duration;
use tracing::{debug, error, info, warn};

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

/// Service for handling periodic updates of Master Lists
#[derive(Debug, Clone)]
pub struct PeriodicUpdater {
    fetcher: MasterListFetcher,
}

impl PeriodicUpdater {
    /// Create a new periodic updater
    pub fn new() -> Result<Self, CscaValidationError> {
        let fetcher = MasterListFetcher::new()?;
        Ok(Self { fetcher })
    }

    /// Create updater with existing fetcher
    pub fn with_fetcher(fetcher: MasterListFetcher) -> Self {
        Self { fetcher }
    }

    /// Check if Master List needs updating
    pub fn needs_update(master_list: Option<&MasterList>) -> bool {
        master_list.map(|ml| !ml.is_valid()).unwrap_or(true)
    }

    /// Automatically update German Master List from BSI if needed
    pub async fn auto_update_german_master_list(
        &self,
        current_master_list: Option<&MasterList>,
    ) -> Result<Option<MasterList>, CscaValidationError> {
        if !Self::needs_update(current_master_list) {
            info!("Master List is still valid, no update needed");
            return Ok(None);
        }

        info!("Master List needs updating, fetching from BSI");

        // Try to fetch the new Master List with retry logic
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 3;

        while attempts < MAX_ATTEMPTS {
            attempts += 1;

            match self.fetcher.fetch_german_master_list().await {
                Ok(master_list) => {
                    info!(
                        "Successfully updated Master List from BSI (attempt {})",
                        attempts
                    );
                    return Ok(Some(master_list));
                }
                Err(e) => {
                    error!("Failed to fetch Master List (attempt {}): {}", attempts, e);
                    if attempts < MAX_ATTEMPTS {
                        warn!("Retrying in 30 seconds...");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(None)
    }

    /// Schedule periodic Master List updates from BSI
    pub async fn start_periodic_updates(
        &self,
        update_interval_hours: u64,
        update_callback: impl Fn(Result<MasterList, CscaValidationError>) + Send + 'static,
    ) -> Result<(), CscaValidationError> {
        info!(
            "Starting periodic Master List updates every {} hours",
            update_interval_hours
        );

        // Perform initial update
        let initial_result = self.fetcher.fetch_german_master_list().await;
        match &initial_result {
            Ok(_) => info!("Initial Master List update completed successfully"),
            Err(e) => warn!("Initial Master List update failed: {}", e),
        }
        update_callback(initial_result);

        // Clone the fetcher for the background task
        let fetcher_clone = self.fetcher.clone();
        let interval_duration = Duration::from_secs(update_interval_hours * 3600);

        // Spawn background task for periodic updates
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first tick since we already did the initial update
            interval.tick().await;

            loop {
                interval.tick().await;
                debug!("Running scheduled Master List update");

                let result = fetcher_clone.fetch_german_master_list().await;
                match &result {
                    Ok(_) => {
                        info!("Scheduled Master List update completed successfully");
                    }
                    Err(e) => {
                        error!("Scheduled Master List update failed: {}", e);
                    }
                }
                update_callback(result);
            }
        });

        info!(
            "Periodic updates started (running every {} hours)",
            update_interval_hours
        );

        Ok(())
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

impl Default for PeriodicUpdater {
    fn default() -> Self {
        Self::new().expect("Failed to create default periodic updater")
    }
}
