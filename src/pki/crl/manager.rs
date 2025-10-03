use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use tracing::{debug, info, warn};
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
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            crl_cache: HashMap::new(),
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Create a new CRL manager with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .expect("Failed to create HTTP client"),
            crl_cache: HashMap::new(),
            request_timeout: Duration::from_secs(timeout_secs),
        }
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
                debug!("Using cached CRL from {}", distribution_point);
                return Ok(cached_crl.clone());
            } else {
                debug!(
                    "Cached CRL from {} is expired, fetching new one",
                    distribution_point
                );
            }
        }

        // Fetch CRL
        let crl_entry = fetch_crl(&self.client, distribution_point, self.request_timeout).await?;

        // Cache the CRL
        self.crl_cache
            .insert(distribution_point.to_string(), crl_entry.clone());

        Ok(crl_entry)
    }

    /// Check if a certificate is revoked by fetching and validating its CRLs
    ///
    /// Tries distribution points in parallel for better performance
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

        // Fetch CRLs from all distribution points in parallel
        let results =
            fetch_crls_parallel(&self.client, &distribution_points, self.request_timeout).await;

        // Cache fetched CRLs and process results
        for (dp, fetch_result) in results {
            match fetch_result {
                Ok(crl_entry) => {
                    // Cache the CRL
                    self.crl_cache.insert(dp.clone(), crl_entry.clone());

                    // Find the issuer certificate to verify CRL signature
                    let issuer_subject = format!("{}", cert.tbs_certificate.issuer);

                    match trust_store.get_cert_by_subject(&issuer_subject).await {
                        Ok(Some(issuer_entry)) => {
                            let issuer_cert = issuer_entry.parse()?;

                            // Verify CRL signature
                            match crl_entry.verify_signature(&issuer_cert) {
                                Ok(true) => {
                                    // Check if certificate is revoked
                                    let serial = cert.tbs_certificate.serial.to_bytes_be();
                                    if let Some(revocation_info) =
                                        crl_entry.is_certificate_revoked(&serial)
                                        && revocation_info.revoked
                                    {
                                        if let Some(reason) = revocation_info.reason {
                                            info!("Certificate is revoked. Reason: {:?}", reason);
                                        }
                                        return Ok(true); // Certificate is revoked
                                    }
                                }
                                Ok(false) => {
                                    warn!("CRL signature verification failed for {}", dp);
                                }
                                Err(e) => {
                                    warn!("CRL signature verification error for {}: {}", dp, e);
                                }
                            }
                        }
                        Ok(None) => {
                            warn!(
                                "Issuer certificate not found in trust store for CRL verification"
                            );
                        }
                        Err(e) => {
                            warn!("Error retrieving issuer certificate: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch CRL from {}: {}", dp, e);
                    continue; // Try next distribution point
                }
            }
        }

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
                    info!("Certificate is revoked according to CRL");
                    Ok(false) // Certificate is not valid
                } else {
                    info!("Certificate is not revoked according to CRL");
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
                    warn!(
                        "CRL validation failed ({}), allowing certificate (fallback mode)",
                        e
                    );
                    Ok(true) // Allow certificate when CRL is unavailable
                } else {
                    warn!("CRL validation failed ({}), rejecting certificate", e);
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
                        info!(
                            "Removed revoked certificate with serial: {:?}",
                            hex::encode(&serial)
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
                    warn!("CRL check failed: {}", e);
                }
            }
        }

        info!(
            "Removed {} revoked certificates from trust store",
            removed_count
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
        info!("CRL cache cleared");
    }

    /// Remove expired CRLs from cache
    pub fn cleanup_cache(&mut self) -> usize {
        let initial_size = self.crl_cache.len();
        self.crl_cache.retain(|_, crl| crl.is_valid());
        let removed = initial_size - self.crl_cache.len();

        if removed > 0 {
            info!("Removed {} expired CRLs from cache", removed);
        }

        removed
    }
}

impl Default for CrlManager {
    fn default() -> Self {
        Self::new()
    }
}
