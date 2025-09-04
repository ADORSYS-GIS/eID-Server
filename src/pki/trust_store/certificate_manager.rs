use std::collections::HashMap;
use std::io::Cursor;

use crate::pki::trust_store::error::TrustStoreError;
use crate::pki::trust_store::models::CSCAPublicKeyInfo;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

pub struct CertificateManager {
    certificates: HashMap<String, CSCAPublicKeyInfo>,
    serial_to_ski: HashMap<String, String>,
}

impl CertificateManager {
    pub fn new(certificates: HashMap<String, CSCAPublicKeyInfo>) -> Self {
        let mut serial_to_ski = HashMap::new();
        for cert_info in certificates.values() {
            if let Ok((_, x509)) = X509Certificate::from_der(cert_info.certificate_der.as_ref()) {
                serial_to_ski.insert(
                    x509.tbs_certificate.serial.to_string(),
                    cert_info.subject_key_identifier.clone(),
                );
            }
        }
        Self {
            certificates,
            serial_to_ski,
        }
    }

    pub fn add_certificate(&mut self, cert_info: CSCAPublicKeyInfo) -> Result<(), TrustStoreError> {
        // Validate certificate on insertion
        let (rem, x509_cert) = X509Certificate::from_der(cert_info.certificate_der.as_ref())
            .map_err(|e| {
                TrustStoreError::InvalidCertificate(format!("DER parsing failed: {}", e))
            })?;

        if !rem.is_empty() {
            return Err(TrustStoreError::InvalidCertificate(
                "Certificate contains unparsed data after DER".to_string(),
            ));
        }

        if x509_cert.tbs_certificate.validity.not_after.timestamp() < chrono::Utc::now().timestamp()
        {
            return Err(TrustStoreError::InvalidCertificate(
                "Certificate is already expired".to_string(),
            ));
        }

        let ski = cert_info.subject_key_identifier.clone();
        let serial = x509_cert.tbs_certificate.serial.to_string();

        self.certificates.insert(ski.clone(), cert_info);
        self.serial_to_ski.insert(serial.clone(), ski);
        Ok(())
    }

    pub fn remove_certificate(&mut self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        if let Some(cert_info) = self.certificates.remove(ski) {
            if let Ok((_, x509)) = X509Certificate::from_der(cert_info.certificate_der.as_ref()) {
                self.serial_to_ski
                    .remove(&x509.tbs_certificate.serial.to_string());
            }
            Some(cert_info)
        } else {
            None
        }
    }

    pub fn get_certificate_by_ski(&self, ski: &str) -> Option<CSCAPublicKeyInfo> {
        self.certificates.get(ski).cloned()
    }

    pub fn get_certificate_by_serial_number(
        &self,
        serial_number: &str,
    ) -> Option<CSCAPublicKeyInfo> {
        self.serial_to_ski
            .get(serial_number)
            .and_then(|ski| self.certificates.get(ski).cloned())
    }

    pub fn list_certificates(&self) -> Vec<CSCAPublicKeyInfo> {
        self.certificates.values().cloned().collect()
    }

    pub fn get_certificates(&self) -> &HashMap<String, CSCAPublicKeyInfo> {
        &self.certificates
    }
}

pub fn parse_cert_pem(pem_bytes: &[u8]) -> Result<Vec<u8>, TrustStoreError> {
    let mut cursor = Cursor::new(pem_bytes);
    let (pem, _bytes_read) = Pem::read(&mut cursor).map_err(|e| {
        TrustStoreError::CertificateParsingError(format!("PEM parsing failed: {}", e))
    })?;
    Ok(pem.contents)
}
