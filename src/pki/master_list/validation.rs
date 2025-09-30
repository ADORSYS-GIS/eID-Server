use time::OffsetDateTime;
use tracing::{debug, info, warn};
use x509_parser::prelude::X509Certificate;
use x509_parser::time::ASN1Time;
use x509_parser::verify::verify_signature;

use crate::pki::crl::{CrlError, CrlManager};
use crate::pki::truststore::{CertificateEntry, MemoryTrustStore, TrustStoreError};

/// Helper function to convert x509-parser's ASN1Time to time's OffsetDateTime
pub fn asn1_time_to_offset_datetime(
    asn1_time: ASN1Time,
) -> Result<OffsetDateTime, TrustStoreError> {
    let offset_datetime: OffsetDateTime = asn1_time.to_datetime();
    Ok(offset_datetime)
}

/// Validates a CSCA certificate by checking its signature and trust chain
pub fn validate_csca_certificate(
    cert: &X509Certificate,
    trusted_certs: &[X509Certificate],
) -> Result<bool, TrustStoreError> {
    // Check if this is a self-signed certificate (root CA)
    let is_self_signed = cert.tbs_certificate.issuer == cert.tbs_certificate.subject;

    if is_self_signed {
        // For self-signed certificates, verify the signature against itself
        match verify_signature(
            &cert.tbs_certificate.subject_pki,
            &cert.signature_algorithm,
            &cert.signature_value,
            cert.tbs_certificate.as_ref(),
        ) {
            Ok(()) => {
                debug!("✓ Self-signed CSCA certificate signature is valid");
                return Ok(true);
            }
            Err(e) => {
                debug!(
                    "✗ Self-signed CSCA certificate signature verification failed: {:?}",
                    e
                );
                return Ok(false);
            }
        }
    }

    // For non-self-signed certificates, try to find the issuer in trusted certificates
    for trusted_cert in trusted_certs {
        if trusted_cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
            match verify_signature(
                &trusted_cert.tbs_certificate.subject_pki,
                &cert.signature_algorithm,
                &cert.signature_value,
                cert.tbs_certificate.as_ref(),
            ) {
                Ok(()) => {
                    debug!("✓ CSCA certificate signature verified against trusted issuer");
                    return Ok(true);
                }
                Err(e) => {
                    debug!("✗ CSCA certificate signature verification failed: {:?}", e);
                    continue; // Try other potential issuers
                }
            }
        }
    }

    // If we reach here, either no trusted issuer was found or all signature verifications failed
    warn!("⚠ No trusted issuer found for certificate or signature verification failed");
    Ok(false)
}

/// Validates certificate dates (not_before and not_after)
pub fn validate_certificate_dates(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<bool, TrustStoreError> {
    let now = OffsetDateTime::now_utc();

    // Check if certificate is expired
    if now > not_after {
        warn!(
            "Certificate is expired (not_after: {}), skipping",
            not_after
        );
        return Ok(false);
    }

    // Check if certificate is not yet valid
    if now < not_before {
        warn!(
            "Certificate is not yet valid (not_before: {}), skipping",
            not_before
        );
        return Ok(false);
    }

    Ok(true)
}

/// Validates certificate signature for self-signed certificates
pub fn validate_self_signed_certificate_signature(
    cert: &X509Certificate,
) -> Result<bool, TrustStoreError> {
    let is_self_signed = cert.tbs_certificate.issuer == cert.tbs_certificate.subject;

    if is_self_signed {
        match verify_signature(
            &cert.tbs_certificate.subject_pki,
            &cert.signature_algorithm,
            &cert.signature_value,
            cert.tbs_certificate.as_ref(),
        ) {
            Ok(()) => {
                debug!("✓ Self-signed CSCA certificate signature validation passed");
                Ok(true)
            }
            Err(e) => {
                debug!(
                    "✗ Self-signed CSCA certificate signature validation failed: {:?}, skipping",
                    e
                );
                Ok(false)
            }
        }
    } else {
        info!(
            "Non-self-signed certificate - signature validation requires trust chain (accepting for now)"
        );
        Ok(true)
    }
}

/// Validates multiple CSCA certificates and returns only the valid ones
pub async fn validate_csca_certificates(
    certificates: Vec<CertificateEntry>,
) -> Result<Vec<CertificateEntry>, TrustStoreError> {
    let mut valid_certificates = Vec::new();
    let total_count = certificates.len();

    // Validate each certificate using cross-validation
    for (i, cert_entry) in certificates.iter().enumerate() {
        if let Ok(cert) = cert_entry.parse() {
            // Check validity dates
            let not_before = asn1_time_to_offset_datetime(cert.validity().not_before)?;
            let not_after = asn1_time_to_offset_datetime(cert.validity().not_after)?;

            if !validate_certificate_dates(not_before, not_after)? {
                continue; // Skip expired or not-yet-valid certificates
            }

            // Build a list of other certificates for cross-validation
            let mut other_certs = Vec::new();
            for (j, other_entry) in certificates.iter().enumerate() {
                if i != j
                    && let Ok(other_cert) = other_entry.parse()
                {
                    other_certs.push(other_cert);
                }
            }

            // Perform cross-validation: validate against all other certificates in the batch
            if validate_csca_certificate(&cert, &other_certs)? {
                valid_certificates.push(cert_entry.clone());
            }
        }
    }

    info!(
        "Validated {} out of {} CSCA certificates using cross-validation",
        valid_certificates.len(),
        total_count
    );
    Ok(valid_certificates)
}

/// Validates multiple CSCA certificates with CRL checking and returns only the valid ones
pub async fn validate_csca_certificates_with_crl(
    certificates: Vec<CertificateEntry>,
    trust_store: &MemoryTrustStore,
    enable_crl_checking: bool,
    crl_fallback_enabled: bool,
) -> Result<Vec<CertificateEntry>, TrustStoreError> {
    let mut valid_certificates = Vec::new();
    let total_count = certificates.len();
    let mut crl_manager = CrlManager::new();

    // First, perform standard validation
    let standard_valid_certs = validate_csca_certificates(certificates).await?;

    if !enable_crl_checking {
        info!(
            "CRL checking disabled, returning {} standard-validated certificates",
            standard_valid_certs.len()
        );
        return Ok(standard_valid_certs);
    }

    // Perform CRL validation on standard-validated certificates
    for cert_entry in standard_valid_certs {
        match crl_manager
            .validate_certificate_with_crl(&cert_entry, trust_store, crl_fallback_enabled)
            .await
        {
            Ok(true) => {
                debug!("Certificate passed CRL validation");
                valid_certificates.push(cert_entry);
            }
            Ok(false) => {
                warn!("Certificate failed CRL validation (revoked or invalid)");
                // Certificate is revoked or failed CRL validation, skip it
            }
            Err(CrlError::TrustStore(e)) => {
                warn!("Trust store error during CRL validation: {}", e);
                if crl_fallback_enabled {
                    info!("Adding certificate due to fallback mode");
                    valid_certificates.push(cert_entry);
                }
            }
            Err(e) => {
                warn!("CRL validation error: {}", e);
                if crl_fallback_enabled {
                    info!("Adding certificate due to fallback mode");
                    valid_certificates.push(cert_entry);
                }
            }
        }
    }

    info!(
        "Validated {} out of {} CSCA certificates with CRL checking (fallback: {})",
        valid_certificates.len(),
        total_count,
        crl_fallback_enabled
    );
    Ok(valid_certificates)
}

/// Validates a single certificate with comprehensive checks including CRL
pub async fn validate_single_certificate_comprehensive(
    cert_entry: &CertificateEntry,
    trusted_certs: &[X509Certificate<'_>],
    trust_store: &MemoryTrustStore,
    enable_crl_checking: bool,
    crl_fallback_enabled: bool,
) -> Result<bool, TrustStoreError> {
    // Parse the certificate
    let cert = cert_entry.parse()?;

    // 1. Validate certificate dates
    let not_before = asn1_time_to_offset_datetime(cert.validity().not_before)?;
    let not_after = asn1_time_to_offset_datetime(cert.validity().not_after)?;

    if !validate_certificate_dates(not_before, not_after)? {
        debug!("Certificate failed date validation");
        return Ok(false);
    }

    // 2. Validate certificate signature and trust chain
    if !validate_csca_certificate(&cert, trusted_certs)? {
        debug!("Certificate failed signature/trust chain validation");
        return Ok(false);
    }

    // 3. Perform CRL validation if enabled
    if enable_crl_checking {
        let mut crl_manager = CrlManager::new();
        match crl_manager
            .validate_certificate_with_crl(cert_entry, trust_store, crl_fallback_enabled)
            .await
        {
            Ok(true) => {
                debug!("Certificate passed all validations including CRL");
                Ok(true)
            }
            Ok(false) => {
                info!("Certificate failed CRL validation");
                Ok(false)
            }
            Err(e) => {
                warn!("CRL validation error: {e}");
                if crl_fallback_enabled {
                    warn!("CRL validation failed but fallback enabled, accepting certificate");
                    Ok(true)
                } else {
                    debug!("CRL validation failed and no fallback, rejecting certificate");
                    Ok(false)
                }
            }
        }
    } else {
        debug!("Certificate passed all validations (CRL checking disabled)");
        Ok(true)
    }
}

/// Cleanup revoked certificates from trust store using CRL
pub async fn cleanup_revoked_certificates_from_trust_store(
    trust_store: &MemoryTrustStore,
) -> Result<usize, TrustStoreError> {
    let mut crl_manager = CrlManager::new();

    match crl_manager.cleanup_revoked_certificates(trust_store).await {
        Ok(removed_count) => {
            info!(
                "Successfully removed {} revoked certificates from trust store",
                removed_count
            );
            Ok(removed_count)
        }
        Err(CrlError::TrustStore(e)) => Err(e),
        Err(e) => {
            warn!("CRL cleanup failed: {e}");
            Ok(0)
        }
    }
}
