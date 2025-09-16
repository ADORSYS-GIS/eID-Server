use async_trait::async_trait;
use pem;
use std::collections::{HashMap, HashSet};
use x509_parser::num_bigint::BigUint;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::TrustStore;
use crate::pki::trust_store::error::TrustStoreError;

/// Simple in-memory trust store for certificate management.
pub struct MemoryTrustStore {
    certificates: HashSet<Vec<u8>>,
    // We will keep a map from serial number to the actual certificate DER bytes
    // for efficient lookup by serial number. This avoids parsing every certificate
    // in the HashSet for each lookup.
    serial_to_cert_map: HashMap<Vec<u8>, Vec<u8>>,
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
            serial_to_cert_map: HashMap::new(),
        }
    }

    /// Converts a BigUint to bytes in big-endian format
    fn biguint_to_bytes(serial: &BigUint) -> Vec<u8> {
        serial.to_bytes_be()
    }

    /// Validates a certificate and extracts its serial number.
    fn validate_and_extract_serial(&self, der_bytes: &[u8]) -> Result<Vec<u8>, TrustStoreError> {
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

        Ok(Self::biguint_to_bytes(&x509_cert.tbs_certificate.serial))
    }
}

#[async_trait]
impl TrustStore for MemoryTrustStore {
    async fn add_certificate(
        &mut self,
        cert_bytes: impl AsRef<[u8]> + Send,
    ) -> Result<bool, TrustStoreError> {
        let der_bytes = match pem::parse(cert_bytes.as_ref()) {
            Ok(parsed_pem) => parsed_pem.contents().to_vec(),
            Err(_) => {
                // Silently ignore malformed PEM certificates
                return Ok(true);
            }
        };

        let serial_number = match self.validate_and_extract_serial(&der_bytes) {
            Ok(serial) => serial,
            Err(_) => {
                // Silently ignore malformed certificates
                return Ok(true);
            }
        };

        // If the certificate already exists, silently ignore and return true.
        if self.certificates.contains(&der_bytes) {
            return Ok(true);
        }

        self.certificates.insert(der_bytes.clone());
        self.serial_to_cert_map.insert(serial_number, der_bytes);
        Ok(true)
    }

    async fn remove_certificate(
        &mut self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<bool, TrustStoreError> {
        let identifier_bytes = identifier.as_ref();

        // Try to remove by exact DER bytes
        if self.certificates.remove(identifier_bytes) {
            // Find the corresponding serial number and remove it from the map
            let serial_to_remove = self
                .serial_to_cert_map
                .iter()
                .find_map(|(serial, cert_der)| {
                    if cert_der == identifier_bytes {
                        Some(serial.clone())
                    } else {
                        None
                    }
                });

            if let Some(serial) = serial_to_remove {
                self.serial_to_cert_map.remove(&serial);
            }
            return Ok(true);
        }

        // If not found by DER bytes, try to remove by serial number
        if let Some(cert_der) = self.serial_to_cert_map.remove(identifier_bytes) {
            self.certificates.remove(&cert_der);
            return Ok(true);
        }

        Ok(false)
    }

    async fn certificate(
        &self,
        identifier: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<Option<Vec<u8>>, TrustStoreError> {
        let identifier_bytes = identifier.as_ref();

        // 1. Try to find by serial number (raw bytes)
        if let Some(cert) = self.serial_to_cert_map.get(identifier_bytes) {
            return Ok(Some(cert.clone()));
        }

        // 2. Try to find by exact DER bytes
        if let Some(cert) = self.certificates.get(identifier_bytes) {
            return Ok(Some(cert.clone()));
        }

        Ok(None)
    }

    async fn verify(
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
            let serial_number = self.validate_and_extract_serial(der_bytes)?;

            // Check if the certificate exists in the trust store by DER bytes or serial number
            if !self.certificates.contains(der_bytes)
                && !self.serial_to_cert_map.contains_key(&serial_number)
            {
                return Err(TrustStoreError::CertificateNotFound(
                    "Certificate in chain not found in trust store.".to_string(),
                ));
            }
        }
        Ok(())
    }
}
