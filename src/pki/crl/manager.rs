use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use tracing::{debug, warn};
use x509_parser::prelude::X509Certificate;

use crate::pki::truststore::{CertificateEntry, MemoryTrustStore, TrustStore};

use super::errors::{CrlError, CrlResult};
use super::fetcher::{fetch_crl, fetch_crls_parallel};
use super::parser::{extract_crl_distribution_points, is_valid_crl_url};
use super::types::CrlEntry;

/// CRL fetcher and validator
pub struct CrlManager {
    client: Client,
    /// Cache of fetched CRLs indexed by distribution point URL
    crl_cache: HashMap<String, CrlEntry>,
    /// Timeout for HTTP requests
    request_timeout: Duration,
}

impl CrlManager {
    /// Create a new CRL manager with default settings
    ///
    /// Returns an error if the HTTP client cannot be initialized
    pub fn new() -> CrlResult<Self> {
        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

        Ok(Self {
            client,
            crl_cache: HashMap::new(),
            request_timeout: Duration::from_secs(30),
        })
    }

    /// Create a new CRL manager with custom timeout
    ///
    /// Returns an error if the HTTP client cannot be initialized
    pub fn with_timeout(timeout_secs: u64) -> CrlResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;

        Ok(Self {
            client,
            crl_cache: HashMap::new(),
            request_timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Extract CRL distribution points from a certificate
    pub fn extract_crl_distribution_points(&self, cert: &X509Certificate) -> Vec<String> {
        extract_crl_distribution_points(cert)
    }

    /// Check if a URL is valid for CRL distribution
    pub fn is_valid_crl_url(&self, url: &str) -> bool {
        is_valid_crl_url(url)
    }

    /// Fetch CRL from a distribution point URL
    pub async fn fetch_crl(&mut self, distribution_point: &str) -> CrlResult<CrlEntry> {
        // Check if we have a cached CRL that's still valid
        if let Some(cached_crl) = self.crl_cache.get(distribution_point) {
            if cached_crl.is_valid() {
                debug!("Using cached CRL from {distribution_point}");
                return Ok(cached_crl.clone());
            } else {
                debug!("Cached CRL from {distribution_point} is expired, fetching new one",);
            }
        }

        // Fetch CRL
        let crl_entry = fetch_crl(&self.client, distribution_point, self.request_timeout).await?;

        // Cache the CRL
        self.crl_cache
            .insert(distribution_point.to_string(), crl_entry.clone());

        Ok(crl_entry)
    }

    pub async fn check_certificate_revocation(
        &mut self,
        cert: &X509Certificate<'_>,
        trust_store: &MemoryTrustStore,
    ) -> CrlResult<bool> {
        // Extract CRL distribution points
        let distribution_points = self.extract_crl_distribution_points(cert);

        if distribution_points.is_empty() {
            warn!("No CRL distribution points found in certificate");
            return Err(CrlError::NoDistributionPoint);
        }

        // Get issuer certificate from trust store
        let issuer_subject = cert.tbs_certificate.issuer.to_string();
        let issuer_entry = match trust_store.get_cert_by_subject(&issuer_subject).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                warn!("Issuer certificate not found in trust store for CRL verification");
                return Err(CrlError::Custom(
                    "Issuer certificate not found in trust store".to_string(),
                ));
            }
            Err(e) => {
                warn!("Error retrieving issuer certificate: {e}");
                return Err(CrlError::TrustStore(e));
            }
        };

        let issuer_cert = issuer_entry.parse()?;
        let serial = cert.tbs_certificate.raw_serial();

        // Fetch CRLs from all distribution points in parallel
        let results =
            fetch_crls_parallel(&self.client, &distribution_points, self.request_timeout).await;

        // Process results - cache ONLY after successful verification
        for (dp, fetch_result) in results {
            match fetch_result {
                Ok(crl_entry) => {
                    // Verify CRL signature BEFORE caching
                    match crl_entry.verify_signature(&issuer_cert) {
                        Ok(true) => {
                            debug!("CRL signature verified successfully for {dp}");

                            // ✅ ONLY cache after successful signature verification
                            self.crl_cache.insert(dp.clone(), crl_entry.clone());

                            // Check if certificate is revoked
                            if let Some(revocation_info) = crl_entry.is_certificate_revoked(&serial)
                                && revocation_info.revoked
                            {
                                if let Some(reason) = revocation_info.reason {
                                    ("Certificate is revoked. Reason: {:?}", reason);
                                } else {
                                    ("Certificate is revoked (no reason provided)");
                                }
                                return Ok(true); // Certificate is revoked
                            }

                            // If we get here, certificate is not in this CRL
                            debug!("Certificate not found in CRL from {dp}");
                        }
                        Ok(false) => {
                            warn!("CRL signature verification failed for {dp} - not caching");
                            // Continue to try other distribution points
                        }
                        Err(e) => {
                            warn!("CRL signature verification error for {dp} - not caching: {e}",);
                            // Continue to try other distribution points
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch CRL from {dp}: {e}");
                    // Continue to try other distribution points
                }
            }
        }

        // If we checked all CRLs and found no revocation
        Ok(false)
    }

    /// Validate a certificate against CRL with fallback logic
    pub async fn validate_certificate_with_crl(
        &mut self,
        cert_entry: &CertificateEntry,
        trust_store: &MemoryTrustStore,
        allow_fallback: bool,
    ) -> CrlResult<bool> {
        let cert = cert_entry.parse()?;

        match self.check_certificate_revocation(&cert, trust_store).await {
            Ok(is_revoked) => {
                if is_revoked {
                    ("Certificate is revoked according to CRL");
                    Ok(false) // Certificate is not valid
                } else {
                    ("Certificate is not revoked according to CRL");
                    Ok(true) // Certificate is valid
                }
            }
            Err(CrlError::NoDistributionPoint) => {
                if allow_fallback {
                    warn!("No CRL distribution points found, allowing certificate (fallback mode)");
                    Ok(true) // Allow certificate when no CRL is available
                } else {
                    warn!("No CRL distribution points found, rejecting certificate");
                    Ok(false)
                }
            }
            Err(e) => {
                if allow_fallback {
                    warn!("CRL validation failed ({e}), allowing certificate (fallback mode)");
                    Ok(true) // Allow certificate when CRL is unavailable
                } else {
                    warn!("CRL validation failed ({e}), rejecting certificate");
                    Err(e)
                }
            }
        }
    }

    /// Remove revoked certificates from trust store based on CRL
    pub async fn cleanup_revoked_certificates(
        &mut self,
        trust_store: &MemoryTrustStore,
    ) -> CrlResult<usize> {
        let mut removed_count = 0;

        // Get all certificates from trust store
        let all_certs = trust_store.iter_all_certificates().await?;

        for cert_entry in &all_certs {
            let cert = cert_entry.parse()?;

            match self.check_certificate_revocation(&cert, trust_store).await {
                Ok(true) => {
                    // Certificate is revoked, remove it
                    let serial = cert.tbs_certificate.serial.to_bytes_be();
                    if trust_store.remove_cert(&serial).await? {
                        (
                            "Removed revoked certificate with serial: {:?}",
                            hex::encode(&serial),
                        );
                        removed_count += 1;
                    }
                }
                Ok(false) => {
                    // Certificate is not revoked, keep it
                    debug!("Certificate is valid, keeping in trust store");
                }
                Err(e) => {
                    // CRL check failed, log warning but don't remove certificate
                    warn!("CRL check failed: {e}");
                }
            }
        }

        (
            "Removed {} revoked certificates from trust store",
            removed_count,
        );
        Ok(removed_count)
    }

    /// Get the number of cached CRLs
    pub fn cache_size(&self) -> usize {
        self.crl_cache.len()
    }

    /// Clear the CRL cache
    pub fn clear_cache(&mut self) {
        self.crl_cache.clear();
        ("CRL cache cleared");
    }

    /// Remove expired CRLs from cache
    pub fn cleanup_cache(&mut self) -> usize {
        let initial_size = self.crl_cache.len();
        self.crl_cache.retain(|_, crl| crl.is_valid());
        let removed = initial_size - self.crl_cache.len();

        if removed > 0 {
            ("Removed {removed} expired CRLs from cache.");
        }

        removed
    }
}

impl Default for CrlManager {
    fn default() -> Self {
        // Use a fallback configuration if new() fails
        // This should rarely fail, but we handle it gracefully
        Self::new().unwrap_or_else(|e| {
            warn!("Failed to create default CRL manager: {e}. Using minimal fallback.");
            // Create a basic client without timeout as fallback
            Self {
                client: Client::new(),
                crl_cache: HashMap::new(),
                request_timeout: Duration::from_secs(30),
            }
        })
    }
}
