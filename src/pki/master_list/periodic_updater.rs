use super::MasterListFetcher;
use super::{CscaValidationError, FetcherConfig, MasterList, WebMasterListFetcher};
use crate::config::MasterListConfig;
use std::sync::Arc;
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

/// Service for handling periodic updates of Master Lists
pub struct PeriodicUpdater {
    fetcher: Arc<dyn MasterListFetcher>,
}

impl Clone for PeriodicUpdater {
    fn clone(&self) -> Self {
        Self {
            fetcher: Arc::clone(&self.fetcher),
        }
    }
}

impl PeriodicUpdater {
    /// Create a new periodic updater with default German BSI fetcher
    pub fn new(master_list_config: MasterListConfig) -> Result<Self, CscaValidationError> {
        let config = FetcherConfig::default();
        let fetcher = Arc::new(WebMasterListFetcher::new(config, master_list_config)?);
        Ok(Self { fetcher })
    }

    /// Create updater with existing fetcher
    pub fn with_fetcher(fetcher: Arc<dyn MasterListFetcher>) -> Self {
        Self { fetcher }
    }

    /// Check if Master List needs updating
    pub fn needs_update(master_list: Option<&MasterList>) -> bool {
        master_list.map(|ml| !ml.is_valid()).unwrap_or(true)
    }

    /// Update German Master List from BSI if needed
    pub async fn update_master_list(
        &self,
        current_master_list: Option<&MasterList>,
    ) -> Result<Option<MasterList>, CscaValidationError> {
        if !Self::needs_update(current_master_list) {
            info!("Master List is still valid, no update needed");
            return Ok(None);
        }

        info!("Master List needs updating, fetching from BSI");

        match self.fetcher.fetch_master_list().await {
            Ok(master_list) => {
                info!("Successfully updated Master List from BSI");
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
