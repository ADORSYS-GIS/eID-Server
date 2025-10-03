use ::time::OffsetDateTime;
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

use super::errors::{CrlError, CrlResult};
use super::types::{CrlEntry, RevocationInfo, RevocationReason};

impl CrlEntry {
    /// Check if a certificate serial number is revoked by this CRL
    /// Returns RevocationInfo with details if revoked, None otherwise
    ///
    /// According to ICAO 9303-12 §6.2.5, revocation status should include reason if available
    pub fn is_certificate_revoked(&self, serial_number: &[u8]) -> Option<RevocationInfo> {
        let Ok(crl) = self.parse() else {
            warn!("Failed to parse CRL from DER data");
            return None;
        };

        for revoked_cert in &crl.tbs_cert_list.revoked_certificates {
            let revoked_serial = revoked_cert.user_certificate.to_bytes_be();
            if revoked_serial == serial_number {
                info!(
                    "Certificate with serial {:?} is revoked",
                    hex::encode(serial_number)
                );

                // Extract revocation reason if available (OID: 2.5.29.21)
                let reason = revoked_cert
                    .extensions()
                    .iter()
                    .find(|ext| ext.oid == oid_registry::OID_X509_EXT_REASON_CODE)
                    .and_then(|ext| {
                        // The reason code is an ENUMERATED value
                        // Typically encoded as 0x0A 0x01 0xXX where XX is the reason
                        if ext.value.len() >= 3 && ext.value[0] == 0x0A && ext.value[1] == 0x01 {
                            let reason_code = ext.value[2];
                            RevocationReason::from_u8(reason_code)
                        } else if ext.value.len() == 1 {
                            // Sometimes it's just the raw value
                            RevocationReason::from_u8(ext.value[0])
                        } else {
                            None
                        }
                    });

                if let Some(reason) = reason {
                    info!("Revocation reason: {:?}", reason);
                }

                return Some(RevocationInfo {
                    revoked: true,
                    revocation_date: revoked_cert.revocation_date,
                    reason,
                });
            }
        }
        None
    }

    /// Check if this CRL is still valid (not expired)
    ///
    /// Validates according to ICAO 9303-12 §6.2.2 and §6.2.3:
    /// - thisUpdate must not be in the future (§6.2.2)
    /// - nextUpdate must not have passed (§6.2.3)
    pub fn is_valid(&self) -> bool {
        let Ok(crl) = self.parse() else {
            warn!("Failed to parse CRL from DER data");
            return false;
        };

        let now = OffsetDateTime::now_utc();

        // Check thisUpdate (must not be in the future) - ICAO 9303-12 §6.2.2
        let this_update_time =
            match crate::pki::master_list::validation::asn1_time_to_offset_datetime(
                crl.tbs_cert_list.this_update,
            ) {
                Ok(dt) => dt,
                Err(_) => {
                    warn!("Failed to parse CRL thisUpdate time");
                    return false;
                }
            };

        if now < this_update_time {
            warn!(
                "CRL thisUpdate is in the future: {} (current time: {})",
                this_update_time, now
            );
            return false;
        }

        // Check if CRL has expired (next_update field) - ICAO 9303-12 §6.2.3
        if let Some(next_update) = &crl.tbs_cert_list.next_update {
            let next_update_time =
                match crate::pki::master_list::validation::asn1_time_to_offset_datetime(
                    *next_update,
                ) {
                    Ok(dt) => dt,
                    Err(_) => {
                        warn!("Failed to parse CRL next_update time");
                        return false;
                    }
                };

            if now > next_update_time {
                warn!("CRL is expired (next_update: {})", next_update_time);
                return false;
            }
        }

        true
    }

    /// Verify the CRL signature against the issuing certificate
    ///
    /// Validates according to ICAO 9303-12 §6.2.1 and §6.2.4:
    /// - Verifies cryptographic signature (§6.2.1)
    /// - Checks issuer is authorized for CRL signing via KeyUsage extension (§6.2.4)
    pub fn verify_signature(&self, issuer_cert: &X509Certificate) -> CrlResult<bool> {
        let crl = self.parse()?;

        // Verify that the issuer matches
        if issuer_cert.tbs_certificate.subject != crl.tbs_cert_list.issuer {
            debug!("CRL issuer does not match certificate subject");
            return Ok(false);
        }

        // ICAO 9303-12 §6.2.4: Check Key Usage extension for cRLSign bit
        let mut has_crl_sign = false;

        for ext in issuer_cert.tbs_certificate.extensions() {
            if ext.oid == oid_registry::OID_X509_EXT_KEY_USAGE
                && let x509_parser::extensions::ParsedExtension::KeyUsage(ku) =
                    ext.parsed_extension()
            {
                has_crl_sign = ku.crl_sign();
                break;
            }
        }

        if !has_crl_sign {
            warn!("Issuer certificate not authorized for CRL signing (cRLSign bit not set)");
            return Err(CrlError::UnauthorizedIssuer);
        }

        debug!("Issuer certificate has cRLSign key usage - authorized for CRL signing");

        // Verify the signature - ICAO 9303-12 §6.2.1
        match x509_parser::verify::verify_signature(
            &issuer_cert.tbs_certificate.subject_pki,
            &crl.signature_algorithm,
            &crl.signature_value,
            crl.tbs_cert_list.as_ref(),
        ) {
            Ok(()) => {
                debug!("[OK] CRL signature verification passed");
                Ok(true)
            }
            Err(e) => {
                debug!("[ERROR] CRL signature verification failed: {:?}", e);
                Err(CrlError::SignatureVerification)
            }
        }
    }
}

/// Validate CRL signature against issuer certificate
pub fn validate_crl_signature(
    crl_entry: &CrlEntry,
    issuer_cert: &X509Certificate,
) -> CrlResult<bool> {
    crl_entry.verify_signature(issuer_cert)
}

/// Validate CRL timing (thisUpdate and nextUpdate)
pub fn validate_crl_timing(crl_entry: &CrlEntry) -> bool {
    crl_entry.is_valid()
}
