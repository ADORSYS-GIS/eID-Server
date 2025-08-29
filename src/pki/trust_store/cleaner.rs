use chrono::Utc;

use crate::pki::trust_store::certificate_manager::CertificateManager;

/// Responsible for cleaning up expired certificates from the trust store.
pub struct CertificateCleaner;

impl CertificateCleaner {
    /// Creates a new `CertificateCleaner` instance.
    pub fn new() -> Self {
        Self
    }

    /// Identifies and removes expired certificates from the `CertificateManager`.
    /// Returns a vector of the Subject Key Identifiers of the removed certificates.
    pub fn cleanup_expired_certificates(
        &self,
        manager: &mut CertificateManager,
    ) -> Vec<String> {
        let now = Utc::now();
        let mut removed_skis = Vec::new();

        // Collect SKIs of expired certificates
        let expired_skis: Vec<String> = manager
            .list_certificates()
            .into_iter()
            .filter(|cert| cert.not_after < now)
            .map(|cert| cert.subject_key_identifier)
            .collect();

        // Remove expired certificates
        for ski in expired_skis {
            if manager.remove_certificate(&ski).is_some() {
                removed_skis.push(ski);
            }
        }

        removed_skis
    }
}

impl Default for CertificateCleaner {
    fn default() -> Self {
        Self::new()
    }
}