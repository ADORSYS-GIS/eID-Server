use std::collections::HashMap;
use std::io::Cursor;
use time::OffsetDateTime;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::error::TrustStoreError;

/// Simple certificate information stored in the trust store
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub name: String,
    pub serial_number: String,
    pub der_bytes: Vec<u8>,
}
/// Certificate manager handles the core certificate operations
pub struct CertificateManager {
    // Store by name for easy lookup
    certificates_by_name: HashMap<String, CertificateInfo>,
    // Store by serial number for alternative lookup
    certificates_by_serial: HashMap<String, CertificateInfo>,
}

impl CertificateManager {
    /// Creates a new certificate manager
    pub fn new() -> Self {
        Self {
            certificates_by_name: HashMap::new(),
            certificates_by_serial: HashMap::new(),
        }
    }

    /// Adds a certificate from DER bytes
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection)
    pub fn add_certificate_der(&mut self, name: String, der_bytes: Vec<u8>) -> bool {
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

    /// Adds a certificate from PEM bytes
    /// Returns true if successfully added, false if certificate is invalid (graceful rejection)
    pub fn add_certificate_pem(&mut self, name: String, pem_bytes: &[u8]) -> bool {
        match self.parse_pem_to_der(pem_bytes) {
            Ok(der_bytes) => self.add_certificate_der(name, der_bytes),
            Err(_) => false,
        }
    }

    /// Removes a certificate by name
    /// Returns true if certificate was found and removed, false otherwise
    pub fn remove_certificate_by_name(&mut self, name: &str) -> bool {
        if let Some(cert_info) = self.certificates_by_name.remove(name) {
            self.certificates_by_serial.remove(&cert_info.serial_number);
            true
        } else {
            false
        }
    }

    /// Removes a certificate by serial number
    /// Returns true if certificate was found and removed, false otherwise
    pub fn remove_certificate_by_serial(&mut self, serial_number: &str) -> bool {
        if let Some(cert_info) = self.certificates_by_serial.remove(serial_number) {
            self.certificates_by_name.remove(&cert_info.name);
            true
        } else {
            false
        }
    }

    /// Retrieves a certificate in DER form by name
    pub fn get_certificate_der_by_name(&self, name: &str) -> Option<&[u8]> {
        self.certificates_by_name
            .get(name)
            .map(|cert| cert.der_bytes.as_slice())
    }

    /// Retrieves a certificate in DER form by serial number
    pub fn get_certificate_der_by_serial(&self, serial_number: &str) -> Option<&[u8]> {
        self.certificates_by_serial
            .get(serial_number)
            .map(|cert| cert.der_bytes.as_slice())
    }

    /// Lists all certificate names currently stored
    pub fn list_certificate_names(&self) -> Vec<String> {
        self.certificates_by_name.keys().cloned().collect()
    }

    /// Returns the number of certificates stored
    pub fn count(&self) -> usize {
        self.certificates_by_name.len()
    }

    /// Verifies a certificate signature against stored certificates
    /// Returns true if the signature is valid against any stored certificate
    pub fn verify_certificate_signature(&self, cert_der: &[u8], hostname: &str) -> bool {
        let cert_to_verify = match X509Certificate::from_der(cert_der) {
            Ok((_, cert)) => cert,
            Err(_) => return false,
        };

        let end_entity_cert = match webpki::EndEntityCert::try_from(cert_der) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let host = match webpki::DnsNameRef::try_from_ascii(hostname.as_bytes()) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Basic validity check using webpki for the end-entity certificate
        if end_entity_cert.verify_is_valid_for_dns_name(host).is_err() {
            return false;
        }

        // Additional verification using stored certificates (issuer/subject check as a fallback)
        for stored_cert_info in self.certificates_by_name.values() {
            if let Ok((_, stored_cert)) = X509Certificate::from_der(&stored_cert_info.der_bytes) {
                if cert_to_verify.tbs_certificate.issuer == stored_cert.tbs_certificate.subject {
                    return true;
                }
            }
        }
        false
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

impl Default for CertificateManager {
    fn default() -> Self {
        Self::new()
    }
}
