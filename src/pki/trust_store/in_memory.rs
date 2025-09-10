use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Cursor;
use time::OffsetDateTime;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::error::TrustStoreError;
use crate::pki::trust_store::{CertificateInfo, TrustStore};

/// Simple in-memory trust store for certificate management
pub struct InMemoryTrustStore {
    // Store by name for easy lookup
    certificates_by_name: HashMap<String, CertificateInfo>,
    // Store by serial number for alternative lookup
    certificates_by_serial: HashMap<String, CertificateInfo>,
}

impl Default for InMemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTrustStore {
    /// Creates a new empty in-memory trust store
    pub fn new() -> Self {
        Self {
            certificates_by_name: HashMap::new(),
            certificates_by_serial: HashMap::new(),
        }
    }

    fn validate_and_extract_info(
        &self,
        name: String,
        der_bytes: Vec<u8>,
    ) -> Result<CertificateInfo, TrustStoreError> {
        // Parse and validate the certificate
        let (remaining, x509_cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!("DER parsing failed: {}", e))
        })?;

        // Ensure no unparsed data remains
        if !remaining.is_empty() {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate contains unparsed data after DER".to_string(),
            ));
        }

        // Basic validation - check if certificate is not expired
        if x509_cert.tbs_certificate.validity.not_after.timestamp()
            < OffsetDateTime::now_utc().unix_timestamp()
        {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate is expired".to_string(),
            ));
        }

        let serial_number = x509_cert.tbs_certificate.serial.to_string();

        Ok(CertificateInfo {
            name,
            serial_number,
            der_bytes,
        })
    }

    fn parse_pem_to_der(&self, pem_bytes: &[u8]) -> Result<Vec<u8>, TrustStoreError> {
        let mut cursor = Cursor::new(pem_bytes);
        let (pem, _) = Pem::read(&mut cursor).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!("PEM parsing failed: {}", e))
        })?;
        Ok(pem.contents)
    }
}

#[async_trait]
impl TrustStore for InMemoryTrustStore {
    async fn add_certificate_der(&mut self, name: String, der_bytes: Vec<u8>) -> bool {
        match self.validate_and_extract_info(name, der_bytes) {
            Ok(cert_info) => {
                self.certificates_by_name
                    .insert(cert_info.name.clone(), cert_info.clone());
                self.certificates_by_serial
                    .insert(cert_info.serial_number.clone(), cert_info);
                true
            }
            Err(_) => false,
        }
    }

    async fn add_certificate_pem(&mut self, name: String, pem_bytes: &[u8]) -> bool {
        match self.parse_pem_to_der(pem_bytes) {
            Ok(der_bytes) => self.add_certificate_der(name, der_bytes).await,
            Err(_) => false,
        }
    }

    async fn remove_certificate_by_name(&mut self, name: &str) -> bool {
        if let Some(cert_info) = self.certificates_by_name.remove(name) {
            self.certificates_by_serial.remove(&cert_info.serial_number);
            true
        } else {
            false
        }
    }

    async fn remove_certificate_by_serial(&mut self, serial_number: &str) -> bool {
        if let Some(cert_info) = self.certificates_by_serial.remove(serial_number) {
            self.certificates_by_name.remove(&cert_info.name);
            true
        } else {
            false
        }
    }

    async fn get_certificate_der_by_name(&self, name: &str) -> Option<Vec<u8>> {
        self.certificates_by_name
            .get(name)
            .map(|cert| cert.der_bytes.clone())
    }

    async fn get_certificate_der_by_serial(&self, serial_number: &str) -> Option<Vec<u8>> {
        self.certificates_by_serial
            .get(serial_number)
            .map(|cert| cert.der_bytes.clone())
    }

    async fn list_certificate_names(&self) -> Vec<String> {
        self.certificates_by_name.keys().cloned().collect()
    }

    async fn count(&self) -> usize {
        self.certificates_by_name.len()
    }
}
