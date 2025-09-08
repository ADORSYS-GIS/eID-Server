pub mod certificate_manager;
pub mod error;

use crate::pki::trust_store::certificate_manager::CertificateManager;

/// Simple in-memory trust store for certificate management
pub struct TrustStore {
    certificate_manager: CertificateManager,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore {
    /// Creates a new empty trust store
    pub fn new() -> Self {
        Self {
            certificate_manager: CertificateManager::new(),
        }
    }

    /// Adds a certificate from DER bytes
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection)
    pub fn add_certificate_der(&mut self, name: String, der_bytes: Vec<u8>) -> bool {
        self.certificate_manager
            .add_certificate_der(name, der_bytes)
    }

    /// Adds a certificate from PEM bytes
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection)
    pub fn add_certificate_pem(&mut self, name: String, pem_bytes: &[u8]) -> bool {
        self.certificate_manager
            .add_certificate_pem(name, pem_bytes)
    }

    /// Removes a certificate by name
    /// Returns true if certificate was found and removed, false otherwise
    pub fn remove_certificate_by_name(&mut self, name: &str) -> bool {
        self.certificate_manager.remove_certificate_by_name(name)
    }

    /// Removes a certificate by serial number
    /// Returns true if certificate was found and removed, false otherwise
    pub fn remove_certificate_by_serial(&mut self, serial_number: &str) -> bool {
        self.certificate_manager
            .remove_certificate_by_serial(serial_number)
    }

    /// Retrieves a certificate in DER form by name
    pub fn get_certificate_der_by_name(&self, name: &str) -> Option<&[u8]> {
        self.certificate_manager.get_certificate_der_by_name(name)
    }

    /// Retrieves a certificate in DER form by serial number
    pub fn get_certificate_der_by_serial(&self, serial_number: &str) -> Option<&[u8]> {
        self.certificate_manager
            .get_certificate_der_by_serial(serial_number)
    }

    /// Lists all certificate names currently stored
    pub fn list_certificate_names(&self) -> Vec<String> {
        self.certificate_manager.list_certificate_names()
    }

    /// Returns the number of certificates stored
    pub fn count(&self) -> usize {
        self.certificate_manager.count()
    }
}
