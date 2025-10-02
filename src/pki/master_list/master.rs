use crate::config::MasterListConfig;
use crate::pki::truststore::{TrustStore, TrustStoreError};
use color_eyre::eyre::Result;

use super::fetcher::MasterListFetcher;

/// Error types for master list operations
#[derive(Debug, thiserror::Error)]
pub enum MasterListError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("ZIP archive error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("X.509 parsing error: {0}")]
    X509(#[from] x509_parser::prelude::X509Error),

    #[error("Master list parsing error: {message}")]
    Parser { message: String },

    #[error("URL parsing error: {0}")]
    Url(#[from] url::ParseError),

    #[error("No valid CSCA certificates found in master list")]
    NoValidCertificates,
}

/// Master list handler for CSCA certificate validation
pub struct MasterListHandler<T: TrustStore> {
    fetcher: MasterListFetcher,
    truststore: T,
}

impl<T: TrustStore> MasterListHandler<T> {
    /// Create a new master list handler with configuration
    pub fn new(config: &MasterListConfig, truststore: T) -> Self {
        Self {
            fetcher: MasterListFetcher::new(config.master_list_url.clone()),
            truststore,
        }
    }

    /// Process master list: fetch, extract, validate, and store CSCA certificates
    pub async fn process_master_list(&self) -> Result<usize, MasterListError> {
        // Step 1: Fetch master list
        let zip_data = self.fetcher.fetch_master_list().await?;

        // Step 2: Extract CSCA certificates
        let certificates = self.fetcher.extract_csca_certificates(zip_data).await?;

        // Step 3: Validate CSCA certificates
        let valid_certificates =
            super::validation::validate_csca_certificates(certificates).await?;

        // Step 4: Check for duplicates and add new certificates to trust store
        let mut new_certificates = Vec::new();
        for cert in valid_certificates {
            // Check if certificate already exists in trust store
            match self
                .truststore
                .get_cert_by_serial(&cert.serial_number)
                .await?
            {
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

        let added_count = self
            .truststore
            .add_certs(new_certificates.into_iter())
            .await?;

        Ok(added_count)
    }

    /// Remove expired CSCA certificates from the trust store
    pub async fn cleanup_expired_certificates(&self) -> Result<usize, MasterListError> {
        // Get all certificates from the trust store
        let all_certificates = self.truststore.iter_all_certificates().await?;
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
                    if self
                        .truststore
                        .remove_cert(&cert_entry.serial_number)
                        .await?
                    {
                        removed_count += 1;
                    }
                }
            }
        }

        Ok(removed_count)
    }

    /// Verify a certificate chain against the CSCA certificates in the trust store
    pub async fn verify_certificate_chain<I, D>(
        &self,
        der_chain: I,
    ) -> Result<bool, MasterListError>
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send,
    {
        Ok(self.truststore.verify(der_chain).await?)
    }

    /// Get a CSCA certificate by its serial number
    pub async fn get_certificate_by_serial(
        &self,
        serial_number: impl AsRef<[u8]> + Send,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, MasterListError> {
        Ok(self.truststore.get_cert_by_serial(serial_number).await?)
    }

    /// Get a CSCA certificate by its subject DN
    pub async fn get_certificate_by_subject(
        &self,
        subject: &str,
    ) -> Result<Option<crate::pki::truststore::CertificateEntry>, MasterListError> {
        Ok(self.truststore.get_cert_by_subject(subject).await?)
    }

    /// Clear all certificates from the trust store
    pub async fn clear_trust_store(&self) -> Result<(), MasterListError> {
        Ok(self.truststore.clear().await?)
    }
}

impl<T: TrustStore + Default> Default for MasterListHandler<T> {
    fn default() -> Self {
        Self::new(&MasterListConfig::default(), T::default())
    }
}
