pub mod certificate_manager;
pub mod error;
pub mod models;

use std::collections::HashMap;

use crate::pki::trust_store::{
    certificate_manager::CertificateManager, error::TrustStoreError, models::CSCAPublicKeyInfo,
};

/// The main TrustStore struct that orchestrates certificate management,
/// persistence, updates, and cleanup.
pub struct TrustStore {
    certificate_manager: CertificateManager,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore {
    pub fn new() -> Self {
        let certificates = HashMap::new();
        let certificate_manager = CertificateManager::new(certificates);
        Self {
            certificate_manager,
        }
    }

    /// Adds a new CSCA certificate to the trust store.
    pub fn add_certificate_der(&mut self, cert_der: Vec<u8>) -> Result<(), TrustStoreError> {
        let cert_info = CSCAPublicKeyInfo::try_from_der_single(&cert_der)?;
        self.certificate_manager.add_certificate(cert_info)
    }

    pub fn add_certificate_pem(&mut self, cert_pem: &[u8]) -> Result<(), TrustStoreError> {
        let cert_der = crate::pki::trust_store::certificate_manager::parse_cert_pem(cert_pem)?;
        let cert_info = CSCAPublicKeyInfo::try_from_der_single(&cert_der)?;
        self.certificate_manager.add_certificate(cert_info)
    }

    /// Removes a CSCA certificate from the trust store by its subject key identifier.
    pub fn remove_certificate(&mut self, ski: &str) -> Result<(), TrustStoreError> {
        self.certificate_manager
            .remove_certificate(ski)
            .ok_or(TrustStoreError::CertificateNotFound(ski.to_string()))
            .map(|_| ())
    }

    pub fn get_certificate_by_ski(&self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        self.certificate_manager.get_certificate_by_ski(ski)
    }

    pub fn get_certificate_by_serial_number(
        &self,
        serial_number: &str,
    ) -> Option<CSCAPublicKeyInfo> {
        self.certificate_manager
            .get_certificate_by_serial_number(serial_number)
    }

    pub fn list_certificates(&self) -> Vec<CSCAPublicKeyInfo> {
        self.certificate_manager.list_certificates()
    }
}
