use crate::pki::blacklist::{BlacklistError, BlacklistManager};
use crate::pki::defect_list::{DefectListError, DefectListManager};
use crate::pki::truststore::{CertificateEntry, TrustStoreError};
use thiserror::Error;

/// Comprehensive validation error that includes all validation failures
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("Blacklist error: {0}")]
    Blacklist(#[from] BlacklistError),

    #[error("Defect list error: {0}")]
    DefectList(#[from] DefectListError),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Comprehensive document validator that checks against truststore, blacklist, and defect list
#[derive(Debug, Clone)]
pub struct DocumentValidator {
    blacklist_manager: BlacklistManager,
    defect_list_manager: DefectListManager,
}

impl DocumentValidator {
    /// Create a new document validator
    pub fn new(
        blacklist_manager: BlacklistManager,
        defect_list_manager: DefectListManager,
    ) -> Self {
        Self {
            blacklist_manager,
            defect_list_manager,
        }
    }

    /// Validate a single certificate against blacklist and defect list
    pub async fn validate_certificate(
        &self,
        cert: &CertificateEntry,
    ) -> Result<(), ValidationError> {
        tracing::debug!(
            "Validating certificate with serial: {}",
            hex::encode(&cert.serial_number)
        );

        // Check blacklist if loaded
        if self.blacklist_manager.is_loaded().await {
            if let Ok(blacklist) = self.blacklist_manager.get().await {
                crate::pki::blacklist::validate_against_blacklist(cert, &blacklist)?;
                tracing::trace!("Certificate passed blacklist validation");
            }
        } else {
            tracing::warn!("Blacklist not loaded, skipping blacklist validation");
        }

        // Check defect list if loaded
        if self.defect_list_manager.is_loaded().await {
            if let Ok(defect_list) = self.defect_list_manager.get().await {
                crate::pki::defect_list::validate_against_defect_list(cert, &defect_list)?;
                tracing::trace!("Certificate passed defect list validation");
            }
        } else {
            tracing::warn!("Defect list not loaded, skipping defect list validation");
        }

        tracing::info!(
            "Certificate validation successful for serial: {}",
            hex::encode(&cert.serial_number)
        );

        Ok(())
    }

    /// Validate a certificate chain against blacklist and defect list
    pub async fn validate_certificate_chain(
        &self,
        chain: &[CertificateEntry],
    ) -> Result<(), ValidationError> {
        tracing::debug!("Validating certificate chain with {} certificates", chain.len());

        // Check blacklist if loaded
        if self.blacklist_manager.is_loaded().await {
            if let Ok(blacklist) = self.blacklist_manager.get().await {
                crate::pki::blacklist::validation::validate_chain_against_blacklist(chain, &blacklist)?;
                tracing::trace!("Certificate chain passed blacklist validation");
            }
        } else {
            tracing::warn!("Blacklist not loaded, skipping blacklist validation");
        }

        // Check defect list if loaded
        if self.defect_list_manager.is_loaded().await {
            if let Ok(defect_list) = self.defect_list_manager.get().await {
                crate::pki::defect_list::validation::validate_chain_against_defect_list(chain, &defect_list)?;
                tracing::trace!("Certificate chain passed defect list validation");
            }
        } else {
            tracing::warn!("Defect list not loaded, skipping defect list validation");
        }

        tracing::info!("Certificate chain validation successful");

        Ok(())
    }

    /// Check if validation is fully enabled (both lists loaded)
    pub async fn is_fully_enabled(&self) -> bool {
        self.blacklist_manager.is_loaded().await && self.defect_list_manager.is_loaded().await
    }

    /// Get validation status
    pub async fn validation_status(&self) -> ValidationStatus {
        ValidationStatus {
            blacklist_loaded: self.blacklist_manager.is_loaded().await,
            blacklist_entries: self.blacklist_manager.entry_count().await,
            defect_list_loaded: self.defect_list_manager.is_loaded().await,
            defect_list_entries: self.defect_list_manager.entry_count().await,
        }
    }
}

/// Status information for validation components
#[derive(Debug, Clone)]
pub struct ValidationStatus {
    pub blacklist_loaded: bool,
    pub blacklist_entries: usize,
    pub defect_list_loaded: bool,
    pub defect_list_entries: usize,
}

impl ValidationStatus {
    pub fn is_operational(&self) -> bool {
        self.blacklist_loaded && self.defect_list_loaded
    }

    pub fn summary(&self) -> String {
        format!(
            "Blacklist: {} ({} entries), Defect List: {} ({} entries)",
            if self.blacklist_loaded { "loaded" } else { "not loaded" },
            self.blacklist_entries,
            if self.defect_list_loaded { "loaded" } else { "not loaded" },
            self.defect_list_entries
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::blacklist::types::{Blacklist, BlacklistEntry, BlacklistReason};
    use crate::pki::defect_list::types::{DefectEntry, DefectList, DefectType};
    use std::sync::Arc;

    fn create_test_cert(serial: Vec<u8>) -> CertificateEntry {
        CertificateEntry {
            raw: Arc::new(vec![]),
            serial_number: serial,
            subject: "CN=Test".to_string(),
            issuer: "CN=Test CA".to_string(),
        }
    }

    #[tokio::test]
    async fn test_validate_certificate_ok() {
        let blacklist_mgr = BlacklistManager::new();
        let defect_list_mgr = DefectListManager::new();

        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        ));
        blacklist_mgr.set_blacklist(blacklist).await;

        let mut defect_list = DefectList::new();
        defect_list.add_entry(DefectEntry::with_serial(
            "DOC123".to_string(),
            "fedcba9876543210".to_string(),
            DefectType::Manufacturing,
        ));
        defect_list_mgr.set_defect_list(defect_list).await;

        let validator = DocumentValidator::new(blacklist_mgr, defect_list_mgr);

        let cert = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(validator.validate_certificate(&cert).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_certificate_blacklisted() {
        let blacklist_mgr = BlacklistManager::new();
        let defect_list_mgr = DefectListManager::new();

        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "aabbccdd".to_string(),
            BlacklistReason::Compromised,
        ));
        blacklist_mgr.set_blacklist(blacklist).await;

        defect_list_mgr.set_defect_list(DefectList::new()).await;

        let validator = DocumentValidator::new(blacklist_mgr, defect_list_mgr);

        let cert = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(validator.validate_certificate(&cert).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_certificate_defective() {
        let blacklist_mgr = BlacklistManager::new();
        let defect_list_mgr = DefectListManager::new();

        blacklist_mgr.set_blacklist(Blacklist::new()).await;

        let mut defect_list = DefectList::new();
        defect_list.add_entry(DefectEntry::with_serial(
            "DOC123".to_string(),
            "aabbccdd".to_string(),
            DefectType::InvalidSignature,
        ));
        defect_list_mgr.set_defect_list(defect_list).await;

        let validator = DocumentValidator::new(blacklist_mgr, defect_list_mgr);

        let cert = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(validator.validate_certificate(&cert).await.is_err());
    }

    #[tokio::test]
    async fn test_validation_status() {
        let blacklist_mgr = BlacklistManager::new();
        let defect_list_mgr = DefectListManager::new();

        let validator = DocumentValidator::new(blacklist_mgr.clone(), defect_list_mgr.clone());

        let status = validator.validation_status().await;
        assert!(!status.is_operational());

        blacklist_mgr.set_blacklist(Blacklist::new()).await;
        defect_list_mgr.set_defect_list(DefectList::new()).await;

        let status = validator.validation_status().await;
        assert!(status.is_operational());
    }
}