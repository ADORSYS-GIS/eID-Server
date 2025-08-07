use chrono::{DateTime, Utc};
use openssl::x509::X509;
use tracing::{debug, warn};
use x509_parser::{
    oid_registry::OID_X509_COUNTRY_NAME, parse_x509_certificate, prelude::X509Certificate,
};

use super::errors::{TrustStoreError, TrustStoreResult};

/// Certificate validation utilities
pub struct CertificateValidator;

impl CertificateValidator {
    /// Validate that a certificate is signed by its parent
    pub fn validate_certificate_signature(
        child_cert_der: &[u8],
        parent_cert_der: &[u8],
    ) -> TrustStoreResult<()> {
        // Parse certificates to check issuer/subject relationship
        let (_, child_cert) = parse_x509_certificate(child_cert_der).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!(
                "Failed to parse child certificate: {e}",
            ))
        })?;
        let (_, parent_cert) = parse_x509_certificate(parent_cert_der).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!(
                "Failed to parse parent certificate: {e}",
            ))
        })?;

        // Check that the child certificate's issuer matches the parent's subject
        if child_cert.issuer() != parent_cert.subject() {
            return Err(TrustStoreError::CertificateValidationError(
                "Certificate issuer does not match parent subject".to_string(),
            ));
        }

        // Extract parent certificate's public key using OpenSSL
        let parent_x509 = X509::from_der(parent_cert_der).map_err(|e| {
            TrustStoreError::CertificateValidationError(format!(
                "Failed to parse parent certificate with OpenSSL: {e}",
            ))
        })?;

        let parent_public_key = parent_x509.public_key().map_err(|e| {
            TrustStoreError::CertificateValidationError(format!(
                "Failed to extract parent public key: {e}",
            ))
        })?;

        // Parse child certificate with OpenSSL for signature verification
        let child_x509 = X509::from_der(child_cert_der).map_err(|e| {
            TrustStoreError::CertificateValidationError(format!(
                "Failed to parse child certificate with OpenSSL: {e}",
            ))
        })?;

        // Verify the signature
        let signature_valid = child_x509.verify(&parent_public_key).map_err(|e| {
            TrustStoreError::CertificateValidationError(format!(
                "Signature verification failed: {e}",
            ))
        })?;

        if !signature_valid {
            return Err(TrustStoreError::CertificateValidationError(
                "Certificate signature verification failed".to_string(),
            ));
        }

        debug!("Certificate signature validation successful");
        Ok(())
    }

    /// Validate certificate validity periods
    pub fn validate_certificate_validity(cert: &X509Certificate<'_>) -> TrustStoreResult<()> {
        let now = Utc::now();
        let not_before = DateTime::from_timestamp(cert.validity.not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity.not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        if now < not_before {
            return Err(TrustStoreError::CertificateValidationError(
                "Certificate is not yet valid".to_string(),
            ));
        }

        if now > not_after {
            return Err(TrustStoreError::CertificateValidationError(
                "Certificate has expired".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate Link certificate specific extensions according to ICAO 9303
    pub fn validate_link_certificate_extensions(
        cert: &X509Certificate<'_>,
    ) -> TrustStoreResult<()> {
        debug!("Validating ICAO 9303 Link certificate extensions");

        // Check for Basic Constraints extension (should be present and CA=true for Link certificates)
        let mut has_basic_constraints = false;
        let mut is_ca = false;

        // Check for Key Usage extension (should include keyCertSign and cRLSign)
        let mut has_key_usage = false;
        let mut has_cert_sign = false;
        let mut has_crl_sign = false;

        // Check for Certificate Policies extension with ICAO OIDs
        let mut has_cert_policies = false;

        // Iterate through certificate extensions
        for extension in cert.extensions() {
            match extension.oid.to_string().as_str() {
                // Basic Constraints (2.5.29.19)
                "2.5.29.19" => {
                    has_basic_constraints = true;
                    // Parse Basic Constraints to check if CA=true
                    if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                        extension.parsed_extension()
                    {
                        is_ca = bc.ca;
                        debug!("Basic Constraints: CA={}", is_ca);
                    }
                }
                // Key Usage (2.5.29.15)
                "2.5.29.15" => {
                    has_key_usage = true;
                    if let x509_parser::extensions::ParsedExtension::KeyUsage(ku) =
                        extension.parsed_extension()
                    {
                        has_cert_sign = ku.key_cert_sign();
                        has_crl_sign = ku.crl_sign();
                        debug!(
                            "Key Usage: certSign={}, crlSign={}",
                            has_cert_sign, has_crl_sign
                        );
                    }
                }
                // Certificate Policies (2.5.29.32)
                "2.5.29.32" => {
                    has_cert_policies = true;
                    debug!("Certificate Policies extension found");
                    // Additional validation of ICAO-specific policy OIDs could be added here
                }
                // Extended Key Usage (2.5.29.37) - optional but if present should be validated
                "2.5.29.37" => {
                    debug!("Extended Key Usage extension found");
                }
                _ => {
                    // Log other extensions for debugging
                    debug!("Extension found: {}", extension.oid.to_string());
                }
            }
        }

        // Validate required extensions for ICAO 9303 Link certificates
        if !has_basic_constraints {
            return Err(TrustStoreError::CertificateValidationError(
                "Link certificate missing required Basic Constraints extension".to_string(),
            ));
        }

        if !is_ca {
            return Err(TrustStoreError::CertificateValidationError(
                "Link certificate Basic Constraints must have CA=true".to_string(),
            ));
        }

        if !has_key_usage {
            return Err(TrustStoreError::CertificateValidationError(
                "Link certificate missing required Key Usage extension".to_string(),
            ));
        }

        if !has_cert_sign {
            return Err(TrustStoreError::CertificateValidationError(
                "Link certificate Key Usage must include keyCertSign".to_string(),
            ));
        }

        if !has_crl_sign {
            return Err(TrustStoreError::CertificateValidationError(
                "Link certificate Key Usage must include cRLSign".to_string(),
            ));
        }

        // Certificate Policies is recommended but not strictly required for all implementations
        if !has_cert_policies {
            warn!(
                "Link certificate does not have Certificate Policies extension (recommended for ICAO 9303)"
            );
        }

        debug!("ICAO 9303 Link certificate extensions validation successful");
        Ok(())
    }
}

/// Extract country code from X.509 certificate
pub fn extract_country_code(cert: &X509Certificate) -> TrustStoreResult<String> {
    // Try to extract country code from subject
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COUNTRY_NAME {
                if let Ok(country) = attr.attr_value().as_str() {
                    return Ok(country.to_string());
                }
            }
        }
    }

    // Fallback: try issuer
    for rdn in cert.issuer().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COUNTRY_NAME {
                if let Ok(country) = attr.attr_value().as_str() {
                    return Ok(country.to_string());
                }
            }
        }
    }

    Err(TrustStoreError::CertificateParsingError(
        "Could not extract country code from certificate".to_string(),
    ))
}
