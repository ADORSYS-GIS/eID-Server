use super::{CscaInfo, CscaTrustStore, CscaValidationError, MasterList};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Trust store statistics
#[derive(Debug, Clone)]
pub struct TrustStoreStats {
    pub total_certificates: usize,
    pub valid_certificates: usize,
    pub expired_certificates: usize,
    pub countries_count: usize,
    pub certificates_by_country: HashMap<String, usize>,
}

/// Service for managing trust store operations
#[derive(Debug, Clone)]
pub struct TrustStoreManager {
    trust_store: CscaTrustStore,
}

impl TrustStoreManager {
    /// Create a new trust store manager
    pub fn new() -> Result<Self, CscaValidationError> {
        let trust_store = CscaTrustStore::new()?;
        Ok(Self { trust_store })
    }

    /// Create manager with existing trust store
    pub fn with_trust_store(trust_store: CscaTrustStore) -> Self {
        Self { trust_store }
    }

    /// Get reference to trust store
    pub fn trust_store(&self) -> &CscaTrustStore {
        &self.trust_store
    }

    /// Get mutable reference to trust store
    pub fn trust_store_mut(&mut self) -> &mut CscaTrustStore {
        &mut self.trust_store
    }

    /// Update trust store with certificates from current Master List
    pub async fn update_from_master_list(
        &mut self,
        master_list: &MasterList,
    ) -> Result<(), CscaValidationError> {
        info!("Updating trust store from Master List");
        let mut added_count = 0;
        let mut skipped_count = 0;

        // Add all valid CSCA certificates to trust store
        for (country_code, csca_list) in &master_list.csca_certificates {
            for csca in csca_list {
                if csca.is_valid() {
                    // Check if already exists in trust store
                    if !self
                        .trust_store
                        .trusted_certificates
                        .contains_key(&csca.fingerprint().unwrap_or_default())
                    {
                        match self.trust_store.add_trusted_csca(csca.clone()) {
                            Ok(_) => {
                                debug!(
                                    "Added CSCA certificate for country {} to trust store",
                                    country_code
                                );
                                added_count += 1;
                            }
                            Err(e) => {
                                error!(
                                    "Failed to add CSCA certificate for country {}: {}",
                                    country_code, e
                                );
                            }
                        }
                    } else {
                        skipped_count += 1;
                    }
                } else {
                    warn!(
                        "Skipping expired CSCA certificate for country {}",
                        country_code
                    );
                    skipped_count += 1;
                }
            }
        }

        info!(
            "Trust store update complete: {} certificates added, {} skipped",
            added_count, skipped_count
        );
        Ok(())
    }

    /// Get trust store statistics
    pub fn get_stats(&self) -> TrustStoreStats {
        let trusted_certs = self.trust_store.get_all_trusted_csca();
        let valid_count = trusted_certs
            .values()
            .filter(|cert| cert.is_valid())
            .count();
        let expired_count = trusted_certs.len() - valid_count;

        let mut countries = HashMap::new();
        for cert in trusted_certs.values() {
            *countries.entry(cert.country_code.clone()).or_insert(0) += 1;
        }

        TrustStoreStats {
            total_certificates: trusted_certs.len(),
            valid_certificates: valid_count,
            expired_certificates: expired_count,
            countries_count: countries.len(),
            certificates_by_country: countries,
        }
    }

    /// Clean up expired certificates from trust store
    pub async fn cleanup_expired(&mut self) -> Result<usize, CscaValidationError> {
        info!("Cleaning up expired certificates from trust store");
        let removed_count = self.trust_store.cleanup_expired()?;
        info!(
            "Removed {} expired certificates from trust store",
            removed_count
        );
        Ok(removed_count)
    }

    /// Get CSCA certificates for a specific country from Master List
    pub fn get_csca_for_country<'a>(
        &self,
        master_list: &'a MasterList,
        country_code: &str,
    ) -> Option<&'a Vec<CscaInfo>> {
        master_list.get_csca_for_country(country_code)
    }

    /// Get all valid CSCA certificates for a country from Master List
    pub fn get_valid_csca_for_country<'a>(
        &self,
        master_list: &'a MasterList,
        country_code: &str,
    ) -> Vec<&'a CscaInfo> {
        master_list.get_valid_csca_for_country(country_code)
    }
}

impl Default for TrustStoreManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default trust store manager")
    }
}
