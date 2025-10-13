use super::error::BlacklistError;
use super::types::{Blacklist, BlacklistEntry};
use crate::pki::truststore::CertificateEntry;

/// Validate a certificate against the blacklist
pub fn validate_against_blacklist(
    cert: &CertificateEntry,
    blacklist: &Blacklist,
) -> Result<(), BlacklistError> {
    if let Some(entry) = blacklist.is_blacklisted(&cert.serial_number, Some(&cert.issuer)) {
        tracing::warn!(
            "Certificate rejected: blacklisted certificate detected. Serial: {}, Reason: {}",
            hex::encode(&cert.serial_number),
            entry.reason
        );

        return Err(BlacklistError::CertificateBlacklisted {
            reason: format!(
                "Serial: {}, Reason: {}, Added: {}{}",
                hex::encode(&cert.serial_number),
                entry.reason,
                entry.date_added,
                entry
                    .notes
                    .as_ref()
                    .map(|n| format!(", Notes: {}", n))
                    .unwrap_or_default()
            ),
        });
    }

    Ok(())
}

/// Validate multiple certificates against the blacklist
pub fn validate_chain_against_blacklist(
    chain: &[CertificateEntry],
    blacklist: &Blacklist,
) -> Result<(), BlacklistError> {
    for (idx, cert) in chain.iter().enumerate() {
        if let Err(e) = validate_against_blacklist(cert, blacklist) {
            tracing::warn!(
                "Certificate at position {} in chain failed blacklist validation: {}",
                idx,
                e
            );
            return Err(e);
        }
    }

    tracing::debug!(
        "All {} certificates in chain passed blacklist validation",
        chain.len()
    );
    Ok(())
}

/// Check if a serial number is in the blacklist (without full certificate)
pub fn is_serial_blacklisted<'a>(serial: &[u8], blacklist: &'a Blacklist) -> Option<&'a BlacklistEntry> {
    blacklist.find_by_serial(serial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::truststore::CertificateEntry;
    use super::super::types::{BlacklistEntry, BlacklistReason};
    use std::sync::Arc;

    fn create_test_cert(serial: Vec<u8>) -> CertificateEntry {
        CertificateEntry {
            raw: Arc::new(vec![]),
            serial_number: serial,
            subject: "CN=Test".to_string(),
            issuer: "CN=Test CA".to_string(),
        }
    }

    #[test]
    fn test_validate_against_blacklist_ok() {
        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        ));

        let cert = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(validate_against_blacklist(&cert, &blacklist).is_ok());
    }

    #[test]
    fn test_validate_against_blacklist_rejected() {
        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        ));

        let cert = create_test_cert(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert!(validate_against_blacklist(&cert, &blacklist).is_err());
    }

    #[test]
    fn test_validate_chain_against_blacklist() {
        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        ));

        let cert1 = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let cert2 = create_test_cert(vec![0xee, 0xff, 0x00, 0x11]);
        
        let chain = vec![cert1, cert2];
        assert!(validate_chain_against_blacklist(&chain, &blacklist).is_ok());
    }

    #[test]
    fn test_validate_chain_with_blacklisted_cert() {
        let mut blacklist = Blacklist::new();
        blacklist.add_entry(BlacklistEntry::new(
            "aabbccdd".to_string(),
            BlacklistReason::Fraudulent,
        ));

        let cert1 = create_test_cert(vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let cert2 = create_test_cert(vec![0xee, 0xff, 0x00, 0x11]);
        
        let chain = vec![cert1, cert2];
        assert!(validate_chain_against_blacklist(&chain, &blacklist).is_err());
    }
}