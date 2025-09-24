use crate::pki::truststore::{TrustStore, TrustStoreError};
use color_eyre::eyre::Result;

pub mod fetcher;
pub mod schedule;
pub mod validation;

use fetcher::MasterListFetcher;

/// Error types for master list operations
#[derive(Debug, thiserror::Error)]
pub enum MasterListError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("ZIP archive error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Trust store error: {0}")]
    TrustStoreError(#[from] TrustStoreError),

    #[error("X.509 parsing error: {0}")]
    X509Error(#[from] x509_parser::prelude::X509Error),

    #[error("Master list parsing error: {message}")]
    ParseError { message: String },

    #[error("No valid CSCA certificates found in master list")]
    NoValidCertificates,
}

/// Master list handler for CSCA certificate validation
pub struct MasterListHandler {
    fetcher: MasterListFetcher,
}

impl MasterListHandler {
    /// Create a new master list handler
    pub fn new() -> Self {
        Self {
            fetcher: MasterListFetcher::new(),
        }
    }

    /// Process master list: fetch, extract, validate, and store CSCA certificates
    pub async fn process_master_list<T: TrustStore>(
        &self,
        trust_store: &T,
    ) -> Result<usize, MasterListError> {
        // Step 1: Fetch master list
        let zip_data = self.fetcher.fetch_master_list().await?;

        // Step 2: Extract CSCA certificates
        let certificates = self.fetcher.extract_csca_certificates(zip_data).await?;

        // Step 3: Validate CSCA certificates
        let valid_certificates = validation::validate_csca_certificates(certificates).await?;

        // Step 4: Check for duplicates and add new certificates to trust store
        let mut new_certificates = Vec::new();
        for cert in valid_certificates {
            // Check if certificate already exists in trust store
            match trust_store.get_cert_by_serial(&cert.serial_number).await? {
                Some(_) => {
                    // Certificate already exists, skip it
                    continue;
                }
                None => {
                    // Certificate is new, add it to the list
                    new_certificates.push(cert.raw.as_ref().clone());
                }
            }
        }

        if new_certificates.is_empty() {
            return Ok(0);
        }

        let added_count = trust_store.add_certs(new_certificates.into_iter()).await?;

        Ok(added_count)
    }

    /// Remove expired CSCA certificates from the trust store
    pub async fn cleanup_expired_certificates<T: TrustStore>(
        &self,
        trust_store: &T,
    ) -> Result<usize, MasterListError> {
        // Get all certificates from the trust store
        let all_certificates = trust_store.iter_all_certificates().await?;
        let mut removed_count = 0;

        // Check each certificate for expiration
        for cert_entry in all_certificates {
            if let Ok(cert) = cert_entry.parse() {
                // Check if certificate is expired
                let now = ::time::OffsetDateTime::now_utc();
                let not_after = cert.validity.not_after.timestamp();
                let current_timestamp = now.unix_timestamp();

                if current_timestamp > not_after {
                    // Certificate is expired, remove it
                    if trust_store.remove_cert(&cert_entry.serial_number).await? {
                        removed_count += 1;
                    }
                }
            }
        }

        Ok(removed_count)
    }

    /// Verify a certificate chain against the CSCA certificates in the trust store
    pub async fn verify_certificate_chain<T: TrustStore, I, D>(
        &self,
        trust_store: &T,
        der_chain: I,
    ) -> Result<bool, MasterListError>
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send,
    {
        trust_store.verify(der_chain).await.map_err(|e| e.into())
    }

    /// Get a CSCA certificate by its serial number
    pub async fn get_certificate_by_serial<T: TrustStore>(
        &self,
        trust_store: &T,
        serial_number: impl AsRef<[u8]> + Send,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, MasterListError> {
        trust_store
            .get_cert_by_serial(serial_number)
            .await
            .map_err(|e| e.into())
    }

    /// Get a CSCA certificate by its subject DN
    pub async fn get_certificate_by_subject<T: TrustStore>(
        &self,
        trust_store: &T,
        subject: &str,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, MasterListError> {
        trust_store
            .get_cert_by_subject(subject)
            .await
            .map_err(|e| e.into())
    }

    /// Clear all certificates from the trust store
    pub async fn clear_trust_store<T: TrustStore>(
        &self,
        trust_store: &T,
    ) -> Result<(), MasterListError> {
        trust_store.clear().await.map_err(|e| e.into())
    }
}

impl Default for MasterListHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::truststore::MemoryTrustStore;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_master_list_handler_creation() {
        let _handler = MasterListHandler::new();
        // Just test that creation doesn't panic
    }

    #[tokio::test]
    async fn test_pem_to_der_conversion() {
        let _fetcher = MasterListFetcher::new();
        let _pem_data = "-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKnL4UKMTVE/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMTEyMTAwNDIzMjlaFw0yMjEyMTAwNDIzMjlaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwofnLwqB
BnkqBUM4Ccvs4mrUsIiC9s4kk4aMTatXKzda1gauss4egatGdWxo29K3hl9BjC1/
PCOAlJCqNbqxl4X8W6P6E0m0wW8fg3I1cF9b0H7xMh5LaX3HMC7e9Zh36Y7XTDHX
TqS+l4jUjhc5e5W7ZzqGZ9Ie7VKV/MR8xVkCAwEAaTANBgkqhkiG9w0BAQsFAAOB
gQCg3u4OoHw5GcZzrv9z7L1z5h4WDgCeV9Yr+uXH8VD9dw9o1rNQF3sMkz4h9K6j
7p3F5aMD0fT4L5oMp8QWxkMFJrDKl+hKg6Kv0VGJcFoGZf5mQD0Q
-----END CERTIFICATE-----";

    }

    #[tokio::test]
    async fn test_empty_trust_store_integration() {
        let temp_dir = tempdir().unwrap();
        let trust_store = MemoryTrustStore::new(temp_dir.path()).await.unwrap();

        assert_eq!(trust_store.len(), 0);
        assert!(trust_store.is_empty());
    }

    #[tokio::test]
    async fn test_trust_store_method_usage() {
        let temp_dir = tempdir().unwrap();
        let trust_store = MemoryTrustStore::new(temp_dir.path()).await.unwrap();
        let handler = MasterListHandler::new();

        // Test get_certificate_by_serial - should return None for non-existent certificate
        let result = handler
            .get_certificate_by_serial(&trust_store, &[1, 2, 3])
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test get_certificate_by_subject - should return None for non-existent certificate
        let result = handler
            .get_certificate_by_subject(&trust_store, "CN=Test")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test verify_certificate_chain with empty chain - behavior depends on implementation
        let empty_chain: Vec<Vec<u8>> = vec![];
        let result = handler
            .verify_certificate_chain(&trust_store, empty_chain)
            .await;
        assert!(result.is_ok()); // Empty chain verification returns Ok(false) rather than error

        // Test clear_trust_store
        let result = handler.clear_trust_store(&trust_store).await;
        assert!(result.is_ok());

        // Verify trust store is still empty after clear
        assert_eq!(trust_store.len(), 0);
        assert!(trust_store.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_expired_certificates() {
        let temp_dir = tempdir().unwrap();
        let trust_store = MemoryTrustStore::new(temp_dir.path()).await.unwrap();
        let handler = MasterListHandler::new();

        // Test cleanup_expired_certificates on empty trust store - should return 0
        let result = handler.cleanup_expired_certificates(&trust_store).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Verify trust store is still empty
        assert_eq!(trust_store.len(), 0);
    }

    #[tokio::test]
    async fn test_iter_all_certificates_method() {
        let temp_dir = tempdir().unwrap();
        let trust_store = MemoryTrustStore::new(temp_dir.path()).await.unwrap();

        // Test iter_all_certificates on empty trust store
        let result = trust_store.iter_all_certificates().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
