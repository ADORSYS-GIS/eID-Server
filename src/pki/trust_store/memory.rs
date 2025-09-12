use async_trait::async_trait;
use pem;
use std::collections::HashSet;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::TrustStore;
use crate::pki::trust_store::error::TrustStoreError;

/// Simple in-memory trust store for certificate management.
pub struct MemoryTrustStore {
    certificates: HashSet<Vec<u8>>,
}

impl Default for MemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTrustStore {
    /// Creates a new empty in-memory trust store.
    pub fn new() -> Self {
        Self {
            certificates: HashSet::new(),
        }
    }

    /// Validates a certificate and extracts its serial number.
    fn validate_and_extract_serial(&self, der_bytes: &[u8]) -> Result<String, TrustStoreError> {
        let (remaining, x509_cert) = X509Certificate::from_der(der_bytes)
            .map_err(|e| TrustStoreError::CertificateParsingError(e.to_string()))?;

        if !remaining.is_empty() {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate contains unparsed data after DER".to_string(),
            ));
        }

        // Check certificate validity period
        let now_asn1_time = x509_parser::time::ASN1Time::now();

        if x509_cert.tbs_certificate.validity.not_before > now_asn1_time
            || x509_cert.tbs_certificate.validity.not_after < now_asn1_time
        {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate is not currently valid (either not yet active or expired)".to_string(),
            ));
        }

        Ok(x509_cert.tbs_certificate.serial.to_string())
    }
}

#[async_trait]
impl TrustStore for MemoryTrustStore {
    async fn add_certificate(
        &mut self,
        cert_bytes: impl AsRef<[u8]> + Send,
    ) -> Result<bool, TrustStoreError> {
        let der_bytes = if let Ok(parsed_pem) = pem::parse(cert_bytes.as_ref()) {
            parsed_pem.contents().to_vec()
        } else {
            cert_bytes.as_ref().to_vec()
        };

        // If the certificate already exists, silently ignore and return false.
        if self.certificates.contains(&der_bytes) {
            return Ok(false);
        }

        self.certificates.insert(der_bytes);
        Ok(true)
    }

    async fn remove_certificate(
        &mut self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<bool, TrustStoreError> {
        let der_bytes_to_remove = identifier.as_ref().to_vec();
        Ok(self.certificates.remove(&der_bytes_to_remove))
    }

    async fn certificate(
        &self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<Option<Vec<u8>>, TrustStoreError> {
        let identifier_bytes = identifier.as_ref();

        // Attempt to parse the identifier as a serial number or certificate content
        let serial_number_opt = self.validate_and_extract_serial(identifier_bytes).ok();

        for cert_bytes in &self.certificates {
            if cert_bytes == identifier_bytes {
                return Ok(Some(cert_bytes.clone()));
            }
            if let Some(ref serial_number) = serial_number_opt
                && let Ok(extracted_serial) = self.validate_and_extract_serial(cert_bytes)
                && extracted_serial == *serial_number
            {
                return Ok(Some(cert_bytes.clone()));
            }
        }
        Ok(None)
    }

    async fn validate(
        &self,
        certificate_chain: impl IntoIterator<Item = impl Into<Vec<u8>>> + Send,
    ) -> Result<(), TrustStoreError> {
        let chain_vec: Vec<Vec<u8>> = certificate_chain.into_iter().map(Into::into).collect();

        if chain_vec.is_empty() {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate chain cannot be empty for validation".to_string(),
            ));
        }

        for der_bytes in &chain_vec {
            self.validate_and_extract_serial(der_bytes)?; // This also checks validity period

            if !self.certificates.contains(der_bytes) {
                return Err(TrustStoreError::CertificateNotFound(
                    "Certificate in chain not found in trust store.".to_string(),
                ));
            }
        }
        Ok(())
    }
}
