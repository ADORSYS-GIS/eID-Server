pub mod error;
pub mod in_memory;
pub mod test;

use async_trait::async_trait;

/// Certificate information stored in the trust store
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub name: String,
    pub serial_number: String,
    pub der_bytes: Vec<u8>,
}

/// Abstract interface for certificate management
#[async_trait]
pub trait TrustStore: Send + Sync {
    /// Adds a certificate from DER bytes.
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection).
    async fn add_certificate_der(&mut self, name: String, der_bytes: Vec<u8>) -> bool;

    /// Adds a certificate from PEM bytes.
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection).
    async fn add_certificate_pem(&mut self, name: String, pem_bytes: &[u8]) -> bool;

    /// Removes a certificate by name.
    /// Returns true if certificate was found and removed, false otherwise.
    async fn remove_certificate_by_name(&mut self, name: &str) -> bool;

    /// Removes a certificate by serial number.
    /// Returns true if certificate was found and removed, false otherwise.
    async fn remove_certificate_by_serial(&mut self, serial_number: &str) -> bool;

    /// Retrieves a certificate in DER form by name.
    async fn get_certificate_der_by_name(&self, name: &str) -> Option<Vec<u8>>;

    /// Retrieves a certificate in DER form by serial number.
    async fn get_certificate_der_by_serial(&self, serial_number: &str) -> Option<Vec<u8>>;

    /// Lists all certificate names currently stored.
    async fn list_certificate_names(&self) -> Vec<String>;

    /// Returns the number of certificates stored.
    async fn count(&self) -> usize;
}
