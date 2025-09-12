use async_trait::async_trait;
use pem;
use std::collections::HashMap;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::error::TrustStoreError;
use crate::pki::trust_store::{CertificateInfo, TrustStore};

/// Simple in-memory trust store for certificate management.
pub struct InMemoryTrustStore {
    certificates_by_name: HashMap<String, CertificateInfo>,
    certificates_by_serial: HashMap<String, CertificateInfo>,
}

impl Default for InMemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTrustStore {
    /// Creates a new empty in-memory trust store.
    pub fn new() -> Self {
        Self {
            certificates_by_name: HashMap::new(),
            certificates_by_serial: HashMap::new(),
        }
    }

    /// Validates a certificate and extracts its information.
    fn validate_and_extract_info(
        &self,
        name: String,
        der_bytes: Vec<u8>,
    ) -> Result<CertificateInfo, TrustStoreError> {
        let (remaining, x509_cert) = X509Certificate::from_der(&der_bytes)
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

        let serial_number = x509_cert.tbs_certificate.serial.to_string();

        Ok(CertificateInfo {
            name,
            serial_number,
            der_bytes,
        })
    }
}

#[async_trait]
impl TrustStore for InMemoryTrustStore {
    async fn add_certificate(
        &mut self,
        name: String,
        cert_bytes: impl AsRef<[u8]> + Send,
    ) -> Result<bool, TrustStoreError> {
        let der_bytes = if let Ok(parsed_pem) = pem::parse(cert_bytes.as_ref()) {
            parsed_pem.contents().to_vec()
        } else {
            cert_bytes.as_ref().to_vec()
        };

        let cert_info = self.validate_and_extract_info(name, der_bytes)?;

        if self.certificates_by_name.contains_key(&cert_info.name)
            || self
                .certificates_by_serial
                .contains_key(&cert_info.serial_number)
        {
            return Ok(false);
        }

        self.certificates_by_name
            .insert(cert_info.name.clone(), cert_info.clone());
        self.certificates_by_serial
            .insert(cert_info.serial_number.clone(), cert_info);

        Ok(true)
    }

    async fn remove_certificate(&mut self, identifier: &str) -> Result<bool, TrustStoreError> {
        let mut removed = false;
        if let Some(cert_info) = self.certificates_by_name.remove(identifier) {
            self.certificates_by_serial.remove(&cert_info.serial_number);
            removed = true;
        } else if let Some(cert_info) = self.certificates_by_serial.remove(identifier) {
            self.certificates_by_name.remove(&cert_info.name);
            removed = true;
        }
        Ok(removed)
    }

    async fn certificate(&self, identifier: &str) -> Result<Option<Vec<u8>>, TrustStoreError> {
        if let Some(cert) = self.certificates_by_name.get(identifier) {
            Ok(Some(cert.der_bytes.clone()))
        } else if let Some(cert) = self.certificates_by_serial.get(identifier) {
            Ok(Some(cert.der_bytes.clone()))
        } else {
            Ok(None)
        }
    }

    async fn validate(&self, certificate_chain: &[Vec<u8>]) -> Result<(), TrustStoreError> {
        if certificate_chain.is_empty() {
            return Err(TrustStoreError::CertificateParsingError(
                "Certificate chain cannot be empty for validation".to_string(),
            ));
        }

        for der_bytes in certificate_chain {
            let (_, x509_cert) = X509Certificate::from_der(der_bytes)
                .map_err(|e| TrustStoreError::CertificateParsingError(e.to_string()))?;

            // Check validity period
            let now_asn1_time = x509_parser::time::ASN1Time::now();

            if x509_cert.tbs_certificate.validity.not_before > now_asn1_time
                || x509_cert.tbs_certificate.validity.not_after < now_asn1_time
            {
                return Err(TrustStoreError::CertificateParsingError(
                    "Certificate in chain is not currently valid (either not yet active or expired)".to_string(),
                ));
            }

            let serial_number = x509_cert.tbs_certificate.serial.to_string();
            let subject = x509_cert.tbs_certificate.subject.to_string();

            // Check if the certificate exists in the trust store by serial or subject
            if !self.certificates_by_serial.contains_key(&serial_number)
                && !self
                    .certificates_by_name
                    .values()
                    .any(|info| info.name == subject)
            {
                return Err(TrustStoreError::CertificateNotFound(format!(
                    "Certificate with serial {serial_number} or subject {subject} not found in trust store."
                )));
            }
        }
        Ok(())
    }
}
