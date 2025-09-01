use std::collections::HashMap;

use crate::pki::trust_store::models::CSCAPublicKeyInfo;

/// Manages the collection of CSCA certificates in the trust store.
pub struct CertificateManager {
    certificates: HashMap<String, CSCAPublicKeyInfo>,
}

impl CertificateManager {
    /// Creates a new `CertificateManager` with an initial set of certificates.
    pub fn new(certificates: HashMap<String, CSCAPublicKeyInfo>) -> Self {
        Self { certificates }
    }

    /// Adds a certificate to the manager. If a certificate with the same
    /// Subject Key Identifier already exists, it will be overwritten.
    pub fn add_certificate(&mut self, cert_info: CSCAPublicKeyInfo) {
        self.certificates
            .insert(cert_info.subject_key_identifier.clone(), cert_info);
    }

    /// Removes a certificate from the manager by its Subject Key Identifier.
    /// Returns the removed certificate if found.
    pub fn remove_certificate(&mut self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        self.certificates.remove(ski)
    }

    /// Retrieves a certificate by its Subject Key Identifier.
    pub fn get_certificate(&self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        self.certificates.get(ski).cloned()
    }

    /// Returns a vector of all certificates currently in the manager.
    pub fn list_certificates(&self) -> Vec<CSCAPublicKeyInfo> {
        self.certificates.values().cloned().collect()
    }

    /// Returns a reference to the internal HashMap of certificates.
    pub fn get_certificates(&self) -> &HashMap<String, CSCAPublicKeyInfo> {
        &self.certificates
    }

    /// Clears all certificates from the manager.
    pub fn clear_certificates(&mut self) {
        self.certificates.clear();
    }
}
