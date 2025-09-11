use super::master_list_fetcher::MasterListFetcher;
use super::periodic_updater::{MasterListUpdateStatus, PeriodicUpdater};
use super::trust_store_manager::{TrustStoreManager, TrustStoreStats};
use super::validator::{CertificateValidator, ValidationResult};
use super::{CscaInfo, CscaValidationError, MasterList, MasterListParser};
use async_trait::async_trait;
use openssl::x509::X509;
use std::path::Path;
use tokio::fs;
use tracing::{info, warn};

/// CSCA validation service for managing Master Lists and trust stores
#[derive(Debug, Clone)]
pub struct CscaValidationService {
    /// Master List fetcher for downloading from remote sources
    fetcher: MasterListFetcher,
    /// Certificate validator for trust chain validation
    validator: CertificateValidator,
    /// Trust store manager for certificate storage and operations
    trust_store_manager: TrustStoreManager,
    /// Periodic updater for scheduled Master List updates
    updater: PeriodicUpdater,
    /// Current Master List
    master_list: Option<MasterList>,
}

impl CscaValidationService {
    /// Create a new CSCA validation service
    pub fn new() -> Result<Self, CscaValidationError> {
        let fetcher = MasterListFetcher::new()?;
        let validator = CertificateValidator::new()?;
        let trust_store_manager = TrustStoreManager::new()?;
        let updater = PeriodicUpdater::new()?;

        Ok(Self {
            fetcher,
            validator,
            trust_store_manager,
            updater,
            master_list: None,
        })
    }

    /// Load Master List from file
    pub async fn load_master_list_from_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
    ) -> Result<(), CscaValidationError> {
        let content = fs::read_to_string(file_path).await?;
        self.load_master_list_from_string(&content).await
    }

    /// Load Master List from string content
    pub async fn load_master_list_from_string(
        &mut self,
        content: &str,
    ) -> Result<(), CscaValidationError> {
        info!("Loading Master List from content");

        let master_list = MasterListParser::parse_auto(content)?;
        info!(
            "Parsed Master List version {} with {} countries",
            master_list.version,
            master_list.csca_certificates.len()
        );

        // Validate Master List is not expired
        if !master_list.is_valid() {
            warn!(
                "Master List has expired, next update was: {:?}",
                master_list.next_update
            );
        }

        self.master_list = Some(master_list);
        self.update_trust_store_from_master_list().await?;

        Ok(())
    }

    /// Fetch and load German Master List from BSI website
    pub async fn fetch_german_master_list(&mut self) -> Result<(), CscaValidationError> {
        let master_list = self.fetcher.fetch_german_master_list().await?;
        self.master_list = Some(master_list);
        self.update_trust_store_from_master_list().await?;
        Ok(())
    }

    /// Update trust store with certificates from current Master List
    async fn update_trust_store_from_master_list(&mut self) -> Result<(), CscaValidationError> {
        let Some(ref master_list) = self.master_list else {
            return Err(CscaValidationError::MasterListParse(
                "No Master List loaded".to_string(),
            ));
        };

        self.trust_store_manager
            .update_from_master_list(master_list)
            .await
    }

    /// Validate a certificate using the trust store with full chain validation
    pub fn validate_certificate(&self, cert: &X509) -> Result<bool, CscaValidationError> {
        self.validator.validate_certificate(cert)
    }

    /// Validate a certificate from DER bytes
    pub fn validate_certificate_der(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError> {
        self.validator.validate_certificate_der(cert_der)
    }

    /// Validate CSCA Link certificates and establish trust chains
    pub fn validate_link_certificates(&self) -> Result<Vec<ValidationResult>, CscaValidationError> {
        let Some(ref master_list) = self.master_list else {
            return Err(CscaValidationError::MasterListParse(
                "No Master List loaded".to_string(),
            ));
        };

        self.validator.validate_link_certificates(master_list)
    }

    /// Get CSCA certificates for a specific country
    pub fn get_csca_for_country(&self, country_code: &str) -> Option<&Vec<CscaInfo>> {
        let master_list = self.master_list.as_ref().unwrap();

        self.trust_store_manager
            .get_csca_for_country(master_list, country_code)
    }

    /// Get all valid CSCA certificates for a country
    pub fn get_valid_csca_for_country(&self, country_code: &str) -> Vec<&CscaInfo> {
        let Some(ref master_list) = self.master_list else {
            return Vec::new();
        };

        self.trust_store_manager
            .get_valid_csca_for_country(master_list, country_code)
    }

    /// Get current Master List
    pub fn get_master_list(&self) -> Option<&MasterList> {
        self.master_list.as_ref()
    }

    /// Get trust store statistics
    pub fn get_trust_store_stats(&self) -> TrustStoreStats {
        self.trust_store_manager.get_stats()
    }

    /// Clean up expired certificates from trust store
    pub async fn cleanup_expired_certificates(&mut self) -> Result<usize, CscaValidationError> {
        self.trust_store_manager.cleanup_expired().await
    }

    /// Check if Master List needs updating
    pub fn needs_master_list_update(&self) -> bool {
        PeriodicUpdater::needs_update(self.master_list.as_ref())
    }

    /// Automatically update German Master List from BSI if needed
    pub async fn auto_update_german_master_list(&mut self) -> Result<bool, CscaValidationError> {
        match self
            .updater
            .auto_update_german_master_list(self.master_list.as_ref())
            .await?
        {
            Some(master_list) => {
                self.master_list = Some(master_list);
                self.update_trust_store_from_master_list().await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Schedule periodic Master List updates from BSI
    pub async fn start_periodic_updates(
        &mut self,
        update_interval_hours: u64,
    ) -> Result<(), CscaValidationError> {
        // Note: This simplified version doesn't automatically update the service's master list
        // The caller should manually check and update the master list when needed
        self.updater
            .start_periodic_updates(update_interval_hours, |result| match result {
                Ok(_) => {
                    tracing::info!("Periodic Master List update completed successfully");
                }
                Err(e) => {
                    tracing::error!("Periodic update failed: {}", e);
                }
            })
            .await
    }

    /// Get Master List update status and statistics
    pub fn get_update_status(&self) -> MasterListUpdateStatus {
        PeriodicUpdater::get_update_status(self.master_list.as_ref())
    }
}

impl Default for CscaValidationService {
    fn default() -> Self {
        Self::new().expect("Failed to create default CSCA validation service")
    }
}

/// Trait for CSCA validation operations
#[async_trait]
pub trait CscaValidator {
    /// Load Master List from file
    async fn load_master_list(&mut self, file_path: &str) -> Result<(), CscaValidationError>;

    /// Validate a certificate
    fn validate_certificate(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError>;

    /// Get CSCA certificates for a country
    fn get_country_csca(&self, country_code: &str) -> Vec<CscaInfo>;
}

#[async_trait]
impl CscaValidator for CscaValidationService {
    async fn load_master_list(&mut self, file_path: &str) -> Result<(), CscaValidationError> {
        self.load_master_list_from_file(file_path).await
    }

    fn validate_certificate(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError> {
        self.validate_certificate_der(cert_der)
    }

    fn get_country_csca(&self, country_code: &str) -> Vec<CscaInfo> {
        self.get_valid_csca_for_country(country_code)
            .into_iter()
            .cloned()
            .collect()
    }
}
