use std::fs;
use tracing::info;

use super::errors::{TrustStoreError, TrustStoreResult};
use super::types::{TrustStoreConfig, TrustStoreData};

/// Storage operations for the trust store
pub struct TrustStoreStorage {
    config: TrustStoreConfig,
}

impl TrustStoreStorage {
    /// Create a new storage handler with configuration
    pub fn new(config: TrustStoreConfig) -> Self {
        Self { config }
    }

    /// Load trust store from disk
    pub async fn load(&self) -> TrustStoreResult<Option<TrustStoreData>> {
        if !self.config.store_path.exists() {
            info!("Trust store file does not exist, starting with empty store");
            return Ok(None);
        }

        let content = fs::read_to_string(&self.config.store_path).map_err(|e| {
            TrustStoreError::LoadError(format!("Failed to read trust store file: {e}"))
        })?;

        let store_data: TrustStoreData = serde_json::from_str(&content).map_err(|e| {
            TrustStoreError::LoadError(format!("Failed to parse trust store JSON: {e}"))
        })?;

        info!(
            "Loaded trust store with {} certificates",
            store_data.certificates.len()
        );
        Ok(Some(store_data))
    }

    /// Save trust store to disk atomically
    pub async fn save(&self, data: &TrustStoreData) -> TrustStoreResult<()> {
        // Create backup directory if it doesn't exist
        if !self.config.backup_dir.exists() {
            fs::create_dir_all(&self.config.backup_dir).map_err(|e| {
                TrustStoreError::SaveError(format!("Failed to create backup directory: {e}"))
            })?;
        }

        // Create backup of current file if it exists
        if self.config.store_path.exists() {
            let backup_name = format!("trust_store_backup_{}.json", data.version);
            let backup_path = self.config.backup_dir.join(backup_name);
            fs::copy(&self.config.store_path, &backup_path)
                .map_err(|e| TrustStoreError::SaveError(format!("Failed to create backup: {e}")))?;
        }

        // Write to temporary file first
        let temp_path = self.config.store_path.with_extension("tmp");
        let json_content = serde_json::to_string_pretty(data).map_err(|e| {
            TrustStoreError::SaveError(format!("Failed to serialize trust store: {e}"))
        })?;

        fs::write(&temp_path, json_content).map_err(|e| {
            TrustStoreError::SaveError(format!("Failed to write temporary file: {e}"))
        })?;

        // Atomic rename
        fs::rename(&temp_path, &self.config.store_path).map_err(|e| {
            TrustStoreError::SaveError(format!("Failed to rename temporary file: {e}"))
        })?;

        info!(
            "Saved trust store with {} certificates (version {})",
            data.certificates.len(),
            data.version
        );
        Ok(())
    }

    /// Get the configuration
    pub fn config(&self) -> &TrustStoreConfig {
        &self.config
    }
}
