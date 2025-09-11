use super::{CscaInfo, CscaLinkCertificate, CscaTrustStore, CscaValidationError, MasterList};
use openssl::x509::X509;
use tracing::{debug, info};

/// Result of certificate validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub certificate_info: CscaInfo,
    pub is_valid: bool,
    pub error: Option<String>,
}

/// Service for validating CSCA certificates and trust chains
#[derive(Debug, Clone)]
pub struct CertificateValidator {
    trust_store: CscaTrustStore,
}

impl CertificateValidator {
    /// Create a new certificate validator
    pub fn new() -> Result<Self, CscaValidationError> {
        let trust_store = CscaTrustStore::new()?;
        Ok(Self { trust_store })
    }

    /// Create validator with existing trust store
    pub fn with_trust_store(trust_store: CscaTrustStore) -> Self {
        Self { trust_store }
    }

    /// Get reference to trust store
    pub fn trust_store(&self) -> &CscaTrustStore {
        &self.trust_store
    }

    /// Get mutable reference to trust store
    pub fn trust_store_mut(&mut self) -> &mut CscaTrustStore {
        &mut self.trust_store
    }

    /// Validate a certificate using the trust store with full chain validation
    pub fn validate_certificate(&self, cert: &X509) -> Result<bool, CscaValidationError> {
        debug!("Validating certificate for country");
        self.trust_store.validate_certificate(cert)
    }

    /// Validate a certificate from DER bytes
    pub fn validate_certificate_der(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError> {
        let cert = X509::from_der(cert_der)?;
        self.validate_certificate(&cert)
    }

    /// Validate CSCA Link certificates and establish trust chains
    pub fn validate_link_certificates(
        &self,
        master_list: &MasterList,
    ) -> Result<Vec<ValidationResult>, CscaValidationError> {
        info!(
            "Validating {} CSCA Link certificates",
            master_list.link_certificates.len()
        );
        let mut results = Vec::new();

        for link_cert in &master_list.link_certificates {
            let result = self.validate_single_link_certificate(link_cert);
            results.push(result);
        }

        let valid_count = results.iter().filter(|r| r.is_valid).count();
        info!(
            "CSCA Link certificate validation complete: {}/{} valid",
            valid_count,
            results.len()
        );

        Ok(results)
    }

    /// Validate a single CSCA Link certificate
    fn validate_single_link_certificate(
        &self,
        link_cert: &CscaLinkCertificate,
    ) -> ValidationResult {
        debug!(
            "Validating CSCA Link certificate from {} to {}",
            link_cert.source_country, link_cert.target_country
        );

        let cert_result = link_cert.certificate_info.to_x509();
        let cert = match cert_result {
            Ok(cert) => cert,
            Err(e) => {
                return ValidationResult {
                    certificate_info: link_cert.certificate_info.clone(),
                    is_valid: false,
                    error: Some(format!("Failed to parse certificate: {e}")),
                };
            }
        };

        // Check if certificate is currently valid (not expired)
        if !link_cert.certificate_info.is_valid() {
            return ValidationResult {
                certificate_info: link_cert.certificate_info.clone(),
                is_valid: false,
                error: Some("Certificate has expired".to_string()),
            };
        }

        // Validate against trust store
        match self.trust_store.validate_certificate(&cert) {
            Ok(true) => ValidationResult {
                certificate_info: link_cert.certificate_info.clone(),
                is_valid: true,
                error: None,
            },
            Ok(false) => ValidationResult {
                certificate_info: link_cert.certificate_info.clone(),
                is_valid: false,
                error: Some("Certificate validation failed".to_string()),
            },
            Err(e) => ValidationResult {
                certificate_info: link_cert.certificate_info.clone(),
                is_valid: false,
                error: Some(format!("Validation error: {e}")),
            },
        }
    }
}

impl Default for CertificateValidator {
    fn default() -> Self {
        Self::new().expect("Failed to create default certificate validator")
    }
}
