use super::MasterListFetcher;
use super::periodic_updater::{MasterListUpdateStatus, PeriodicUpdater};
use super::trust_store_manager::{TrustStoreManager, TrustStoreStats};
use super::validator::{CertificateValidator, ValidationResult};
use super::{CscaInfo, CscaValidationError, MasterList, MasterListParser};
use super::{FetcherConfig, WebMasterListFetcher};
use crate::config::MasterListConfig;
use async_trait::async_trait;
use openssl::x509::X509;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

/// CSCA validation service for managing Master Lists and trust stores
pub struct CscaValidationService {
    /// Master List fetcher for downloading from remote sources
    fetcher: Arc<dyn MasterListFetcher>,
    /// Certificate validator for trust chain validation
    validator: CertificateValidator,
    /// Trust store manager for certificate storage and operations
    trust_store_manager: TrustStoreManager,
    /// Periodic updater for scheduled Master List updates
    updater: PeriodicUpdater,
    /// Current Master List
    master_list: Option<MasterList>,
}

impl Clone for CscaValidationService {
    fn clone(&self) -> Self {
        Self {
            fetcher: Arc::clone(&self.fetcher),
            validator: self.validator.clone(),
            trust_store_manager: self.trust_store_manager.clone(),
            updater: self.updater.clone(),
            master_list: self.master_list.clone(),
        }
    }
}

impl CscaValidationService {
    /// Create a new CSCA validation service with default German BSI fetcher
    pub fn new(master_list_config: MasterListConfig) -> Result<Self, CscaValidationError> {
        let master_list_config_clone = master_list_config.clone();
        Self::with_fetcher(
            Self::create_default_fetcher(master_list_config)?,
            master_list_config_clone,
        )
    }

    /// Create a new CSCA validation service with custom fetcher
    pub fn with_fetcher(
        fetcher: Arc<dyn MasterListFetcher>,
        master_list_config: MasterListConfig,
    ) -> Result<Self, CscaValidationError> {
        let validator = CertificateValidator::new()?;
        let trust_store_manager = TrustStoreManager::new()?;
        let updater = PeriodicUpdater::new(master_list_config)?;

        Ok(Self {
            fetcher,
            validator,
            trust_store_manager,
            updater,
            master_list: None,
        })
    }

    /// Create default fetcher with German BSI support
    fn create_default_fetcher(
        master_list_config: MasterListConfig,
    ) -> Result<Arc<dyn MasterListFetcher>, CscaValidationError> {
        let config = FetcherConfig::default();
        let web_fetcher = WebMasterListFetcher::new(config, master_list_config)?;
        Ok(Arc::new(web_fetcher))
    }

    /// Load Master List from file
    pub async fn load_master_list_from_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
    ) -> Result<(), CscaValidationError> {
        let content = fs::read(file_path).await?;
        self.load_master_list_from_bytes(&content).await
    }

    /// Load Master List from bytes
    pub async fn load_master_list_from_bytes(
        &mut self,
        content: &[u8],
    ) -> Result<(), CscaValidationError> {
        info!("Loading Master List from DER bytes");

        let master_list = MasterListParser::parse_der(content)?;
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

    /// Fetch and load master list from configured sources
    pub async fn fetch_master_list(&mut self) -> Result<(), CscaValidationError> {
        let master_list = self.fetcher.fetch_master_list().await?;
        self.master_list = Some(master_list);
        self.update_trust_store_from_master_list().await?;
        Ok(())
    }

    /// Fetch and load German Master List from BSI website (deprecated - use fetch_master_list instead)
    #[deprecated(note = "Use fetch_master_list() instead for flexibility with multiple sources")]
    pub async fn fetch_german_master_list(&mut self) -> Result<(), CscaValidationError> {
        self.fetch_master_list().await
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

    /// Update German Master List from BSI if needed
    pub async fn update_german_master_list(&mut self) -> Result<bool, CscaValidationError> {
        match self
            .updater
            .update_master_list(self.master_list.as_ref())
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

    /// Get Master List update status and statistics
    pub fn get_update_status(&self) -> MasterListUpdateStatus {
        PeriodicUpdater::get_update_status(self.master_list.as_ref())
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
