pub mod error;
pub mod in_memory;
pub mod test;

use async_trait::async_trait;
use error::TrustStoreError;

/// Certificate information stored in the trust store.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub name: String,
    pub serial_number: String,
    pub der_bytes: Vec<u8>,
}

/// Abstract interface for certificate management
#[async_trait]
pub trait TrustStore: Send + Sync {
    /// Adds a certificate to the trust store.
    ///
    /// This method attempts to automatically detect if the provided `cert_bytes` are DER or PEM
    /// encoded. It then parses, validates, and stores the certificate.
    ///
    /// # Arguments
    /// * `name` - A unique name to identify the certificate in the store.
    /// * `cert_bytes` - The certificate bytes, which can be either DER or PEM encoded.
    ///
    /// # Returns
    /// `Ok(true)` if the certificate was successfully added.
    /// `Ok(false)` if the certificate is a duplicate (already exists by name or serial number).
    /// `Err(TrustStoreError)` if parsing or validation fails, or if there's an I/O error.
    async fn add_certificate(
        &mut self,
        name: String,
        cert_bytes: impl AsRef<[u8]> + Send,
    ) -> Result<bool, TrustStoreError>;

    /// Removes a certificate from the trust store.
    ///
    /// This method attempts to remove a certificate by first trying to match the provided
    /// identifier as a certificate name, and then as a serial number.
    ///
    /// # Arguments
    /// * `identifier` - The name or serial number of the certificate to remove.
    ///
    /// # Returns
    /// `Ok(true)` if the certificate was found and removed.
    /// `Ok(false)` if no certificate matching the identifier was found.
    /// `Err(TrustStoreError)` if an error occurs during the removal process (e.g., I/O errors).
    async fn remove_certificate(&mut self, identifier: &str) -> Result<bool, TrustStoreError>;

    /// Retrieves a DER-encoded certificate from the trust store.
    ///
    /// This method attempts to retrieve a certificate by first trying to match the provided
    /// identifier as a certificate name, and then as a serial number.
    ///
    /// # Arguments
    /// * `identifier` - The name or serial number of the certificate to retrieve.
    ///
    /// # Returns
    /// `Ok(Some(Vec<u8>))` containing the DER-encoded certificate bytes if found.
    /// `Ok(None)` if no certificate matching the identifier was found.
    /// `Err(TrustStoreError)` if an error occurs during the retrieval process (e.g., I/O errors).
    async fn certificate(&self, identifier: &str) -> Result<Option<Vec<u8>>, TrustStoreError>;

    /// Validates a certificate chain against the trust store.
    ///
    /// This method takes a certificate or a chain of certificates and validates them against
    /// the certificates already present in the trust store.
    ///
    /// # Arguments
    /// * `certificate_chain` - A slice of DER-encoded certificate bytes representing the chain
    ///   to validate. The leaf certificate should be the first in the slice.
    ///
    /// # Returns
    /// `Ok(())` if the certificate chain is valid.
    /// `Err(TrustStoreError)` if the chain is invalid or an error occurs during validation.
    async fn validate(&self, certificate_chain: &[Vec<u8>]) -> Result<(), TrustStoreError>;
}
