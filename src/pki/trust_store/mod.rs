pub mod error;
pub mod memory;
#[cfg(test)]
mod test;

use async_trait::async_trait;
use error::TrustStoreError;

/// Abstract interface for certificate management
#[async_trait]
pub trait TrustStore: Send + Sync {
    /// Adds a certificate to the trust store.
    async fn add_certificate(
        &mut self,
        cert_bytes: impl AsRef<[u8]> + Send,
    ) -> Result<bool, TrustStoreError>;

    /// Removes a certificate from the trust store.
    async fn remove_certificate(
        &mut self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<bool, TrustStoreError>;

    /// Retrieves a DER-encoded certificate from the trust store.
    /// This method attempts to retrieve a certificate by its serial number or its content.
    async fn certificate(
        &self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<Option<Vec<u8>>, TrustStoreError>;

    /// Verifies a certificate chain against the trust store.
    async fn verify(
        &self,
        certificate_chain: impl IntoIterator<Item = impl Into<Vec<u8>>> + Send,
    ) -> Result<(), TrustStoreError>;
}
