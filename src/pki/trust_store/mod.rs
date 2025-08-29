pub mod certificate_manager;
pub mod cleaner;
pub mod error;
pub mod models;
pub mod persistence;
pub mod updater;


use log::info;

use crate::pki::trust_store::{
    certificate_manager::CertificateManager, error::TrustStoreError, models::CSCAPublicKeyInfo,
    persistence::TrustStoreRepository,
};

/// The main TrustStore struct that orchestrates certificate management,
/// persistence, updates, and cleanup.
pub struct TrustStore {
    certificate_manager: CertificateManager,
    repository: Box<dyn TrustStoreRepository + Send + Sync>,
}

impl TrustStore {
    /// Creates a new `TrustStore` instance.
    /// It attempts to load existing certificates from the repository.
    /// If loading fails (e.g., file not found or corrupted), it initializes an empty store.
    pub async fn new(repository: Box<dyn TrustStoreRepository + Send + Sync>) -> Result<Self, TrustStoreError> {
        let certificates = repository.load_certificates().await?; // This is the "fail hard" part
        
        let certificate_manager = CertificateManager::new(certificates);

        Ok(Self {
            certificate_manager,
            repository,
        })
    }

    /// Adds a new CSCA certificate to the trust store.
    pub async fn add_certificate(&mut self, cert_info: CSCAPublicKeyInfo) -> Result<(), TrustStoreError> {
        info!("Attempting to add certificate with SKI: {}", cert_info.subject_key_identifier);
        self.certificate_manager.add_certificate(cert_info);
        self.repository.save_certificates(self.certificate_manager.get_certificates()).await?;
        info!("Successfully added and persisted certificate.");
        Ok(())
    }

    /// Removes a CSCA certificate from the trust store by its subject key identifier.
    pub async fn remove_certificate(&mut self, ski: &str) -> Result<(), TrustStoreError> {
        info!("Attempting to remove certificate with SKI: {}", ski);
        self.certificate_manager
            .remove_certificate(ski)
            .ok_or(TrustStoreError::CertificateNotFound(ski.to_string()))?;
        self.repository.save_certificates(self.certificate_manager.get_certificates()).await?;
        info!("Successfully removed and persisted certificate with SKI: {}.", ski);
        Ok(())
    }

    /// Retrieves a CSCA certificate by its subject key identifier.
    pub fn get_certificate(&self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        self.certificate_manager.get_certificate(ski)
    }

    /// Returns a list of all current CSCA certificates in the trust store.
    pub fn list_certificates(&self) -> Vec<CSCAPublicKeyInfo> {
        self.certificate_manager.list_certificates()
    }

    /// Triggers an update of the trust store using master lists.
    pub async fn update_from_master_list(&mut self) -> Result<(), TrustStoreError> {
        // This will be implemented by the updater module
        Err(TrustStoreError::Other("Master list update not yet implemented".to_string()))
    }

    /// Cleans up expired certificates from the trust store.
    pub async fn cleanup_expired_certificates(&mut self) -> Result<(), TrustStoreError> {
        // This will be implemented by the cleaner module
        Err(TrustStoreError::Other("Certificate cleanup not yet implemented".to_string()))
    }
}
