use super::error::DefectListError;
use super::types::{DefectEntry, DefectList};
use crate::pki::truststore::CertificateEntry;

/// Validate a certificate against the defect list
pub fn validate_against_defect_list(
    cert: &CertificateEntry,
    defect_list: &DefectList,
) -> Result<(), DefectListError> {
    if let Some(entry) =
        defect_list.has_defects(Some(&cert.serial_number), Some(&cert.issuer))
    {
        tracing::warn!(
            "Certificate rejected: defective document detected. Serial: {}, Defect: {}",
            hex::encode(&cert.serial_number),
            entry.defect_type
        );

        return Err(DefectListError::DocumentDefective {
            reason: format!(
                "Document: {}, Serial: {}, Defect: {}, Severity: {}, Discovered: {}{}",
                entry.document_number,
                hex::encode(&cert.serial_number),
                entry.defect_type,
                entry.severity,
                entry.date_discovered,
                entry
                    .description
                    .as_ref()
                    .map(|d| format!(", Description: {}", d))
                    .unwrap_or_default()
            ),
        });
    }

    Ok(())
}

/// Validate multiple certificates against the defect list
pub fn validate_chain_against_defect_list(
    chain: &[CertificateEntry],
    defect_list: &DefectList,
) -> Result<(), DefectListError> {
    for (idx, cert) in chain.iter().enumerate() {
        if let Err(e) = validate_against_defect_list(cert, defect_list) {
            tracing::warn!(
                "Certificate at position {} in chain failed defect list validation: {}",
                idx,
                e
            );
            return Err(e);
        }
    }

    tracing::debug!(
        "All {} certificates in chain passed defect list validation",
        chain.len()
    );
    Ok(())
}