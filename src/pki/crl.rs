use std::collections::HashMap;
use std::time::Duration;

use ::time::OffsetDateTime;
use color_eyre::eyre::Result;
use reqwest::Client;
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use url::Url;
use x509_parser::prelude::*;

use crate::pki::truststore::{CertificateEntry, MemoryTrustStore, TrustStore, TrustStoreError};

/// CRL-related errors
#[derive(Error, Debug)]
pub enum CrlError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("CRL parsing failed: {0}")]
    Parse(#[from] X509Error),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("CRL validation failed: {0}")]
    Validation(String),

    #[error("CRL distribution point not found in certificate")]
    NoDistributionPoint,

    #[error("CRL signature verification failed")]
    SignatureVerification,

    #[error("CRL is expired")]
    Expired,

    #[error("Timeout while fetching CRL")]
    Timeout,

    #[error("Custom error: {0}")]
    Custom(String),
}

/// Represents a Certificate Revocation List entry
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// The raw CRL data in DER format
    pub der_data: Vec<u8>,
    /// When this CRL was fetched
    pub fetched_at: OffsetDateTime,
    /// The issuer of this CRL
    pub issuer: String,
    /// Distribution point URL where this CRL was fetched from
    pub distribution_point: String,
}

impl CrlEntry {
    /// Create a new CRL entry from DER data
    pub fn from_der(der_data: Vec<u8>, distribution_point: String) -> Result<Self, CrlError> {
        let (_, crl) = CertificateRevocationList::from_der(&der_data)
            .map_err(|e| CrlError::Parse(e.into()))?;

        let issuer = format!("{}", crl.tbs_cert_list.issuer);

        Ok(Self {
            der_data,
            fetched_at: OffsetDateTime::now_utc(),
            issuer,
            distribution_point,
        })
    }

    /// Check if a certificate serial number is revoked by this CRL
    pub fn is_certificate_revoked(&self, serial_number: &[u8]) -> bool {
        let Ok((_, crl)) = CertificateRevocationList::from_der(&self.der_data) else {
            warn!("Failed to parse CRL from DER data");
            return false;
        };

        for revoked_cert in &crl.tbs_cert_list.revoked_certificates {
            let revoked_serial = revoked_cert.user_certificate.to_bytes_be();
            if revoked_serial == serial_number {
                info!(
                    "Certificate with serial {:?} is revoked",
                    hex::encode(serial_number)
                );
                return true;
            }
        }
        false
    }

    /// Check if this CRL is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        let Ok((_, crl)) = CertificateRevocationList::from_der(&self.der_data) else {
            warn!("Failed to parse CRL from DER data");
            return false;
        };

        let now = OffsetDateTime::now_utc();

        // Check if CRL has expired (next_update field)
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
    pub fn verify_signature(&self, issuer_cert: &X509Certificate) -> Result<bool, CrlError> {
        let Ok((_, crl)) = CertificateRevocationList::from_der(&self.der_data) else {
            return Err(CrlError::Parse(X509Error::InvalidX509Name));
        };

        // Verify that the issuer matches
        if issuer_cert.tbs_certificate.subject != crl.tbs_cert_list.issuer {
            return Ok(false);
        }

        // Verify the signature
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

/// CRL fetcher and validator
pub struct CrlManager {
    client: Client,
    /// Cache of fetched CRLs indexed by distribution point URL
    crl_cache: HashMap<String, CrlEntry>,
    /// Timeout for HTTP requests
    request_timeout: Duration,
}

impl CrlManager {
    /// Create a new CRL manager
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

    pub fn extract_crl_distribution_points(&self, cert: &X509Certificate) -> Vec<String> {
        let mut distribution_points = Vec::new();

        // Look for CRL Distribution Points extension (OID: 2.5.29.31)
        for ext in cert.tbs_certificate.extensions() {
            if ext.oid == oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
                debug!("Found CRL Distribution Points extension, parsing...");

                // Parse using enhanced binary pattern matching
                let mut urls = self.extract_urls_from_der_data(ext.value);

                // Fallback: Extract URLs using regex pattern matching on raw data
                if urls.is_empty() {
                    warn!("Binary parsing failed, using fallback regex method");
                    urls = self.extract_urls_with_regex_fallback(ext.value);
                }

                // Filter and validate URLs
                for url in urls {
                    if self.is_valid_crl_url(&url) {
                        debug!("Found valid CRL distribution point: {}", url);
                        distribution_points.push(url);
                    } else {
                        warn!("Invalid or unsupported CRL URL format: {}", url);
                    }
                }
            }
        }

        if distribution_points.is_empty() {
            debug!("No CRL distribution points found in certificate extensions");
        } else {
            info!(
                "Found {} CRL distribution points",
                distribution_points.len()
            );
        }

        distribution_points
    }

    /// Extract URLs from DER-encoded extension data using binary pattern matching
    /// This method looks for common patterns that indicate HTTP/HTTPS URLs in DER structures
    fn extract_urls_from_der_data(&self, der_data: &[u8]) -> Vec<String> {
        let mut urls = Vec::new();

        // Look for HTTP/HTTPS URL patterns in the DER data

        let http_pattern = b"http://";
        let https_pattern = b"https://";

        // Search for HTTP patterns
        for (i, window) in der_data.windows(http_pattern.len()).enumerate() {
            if window == http_pattern
                && let Some(url) = self.extract_url_from_position(der_data, i)
            {
                urls.push(url);
            }
        }

        // Search for HTTPS patterns
        for (i, window) in der_data.windows(https_pattern.len()).enumerate() {
            if window == https_pattern
                && let Some(url) = self.extract_url_from_position(der_data, i)
            {
                urls.push(url);
            }
        }

        // Remove duplicates while preserving order
        let mut seen = std::collections::HashSet::new();
        urls.retain(|url| seen.insert(url.clone()));

        urls
    }

    /// Extract a complete URL starting from the given position in the DER data
    fn extract_url_from_position(&self, data: &[u8], start_pos: usize) -> Option<String> {
        // Find the end of the URL by looking for common DER delimiters or non-printable characters
        let mut end_pos = start_pos;

        for &byte in &data[start_pos..] {
            // Stop at common DER structure bytes, control characters, or spaces
            if byte == 0x30
                || byte == 0x86
                || byte == 0x82
                || byte == 0x04
                || !(0x20..=0x7E).contains(&byte)
                || byte == b' '
            {
                break;
            }
            end_pos += 1;
        }

        if end_pos > start_pos
            && let Ok(url_str) = String::from_utf8(data[start_pos..end_pos].to_vec())
        {
            // Basic URL validation - must end with reasonable characters
            if url_str.len() > 10
                && (url_str.ends_with(".crl")
                    || url_str.ends_with('/')
                    || url_str.chars().last().is_some_and(|c| c.is_alphanumeric()))
            {
                return Some(url_str);
            }
        }

        None
    }

    /// Fallback method using regex pattern matching for URL extraction
    /// This handles cases where the DER structure is non-standard or compressed
    fn extract_urls_with_regex_fallback(&self, extension_data: &[u8]) -> Vec<String> {
        let mut urls = Vec::new();

        // Convert extension data to string, handling potential binary data
        if let Ok(data_str) = String::from_utf8(extension_data.to_vec()) {
            let url_regex = regex::Regex::new(
                r"https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*[a-zA-Z0-9/]",
            )
            .unwrap();

            for cap in url_regex.captures_iter(&data_str) {
                if let Some(url_match) = cap.get(0) {
                    let url = url_match.as_str().to_string();
                    // Additional cleanup - remove any trailing DER artifacts
                    let clean_url = url
                        .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.')
                        .to_string();
                    if !clean_url.is_empty() {
                        urls.push(clean_url);
                    }
                }
            }
        } else {
            // If UTF-8 conversion fails, try searching for URL patterns in raw bytes
            debug!("Extension data is not valid UTF-8, searching for URL patterns in raw bytes");

            // Look for URL patterns by searching for http/https followed by printable characters
            urls = self.extract_urls_from_der_data(extension_data);
        }

        urls
    }

    /// Validate that the extracted URL is suitable for CRL distribution
    fn is_valid_crl_url(&self, url: &str) -> bool {
        // Basic URL validation
        if url.len() < 10 || (!url.starts_with("http://") && !url.starts_with("https://")) {
            return false;
        }

        // Parse URL to ensure it's well-formed
        if let Ok(parsed_url) = Url::parse(url) {
            // Ensure it has a valid host
            if parsed_url.host().is_none() {
                return false;
            }

            // Additional checks for CRL-specific patterns
            let path = parsed_url.path().to_lowercase();

            if path.ends_with(".crl")
                || path.ends_with('/')
                || path.contains("crl")
                || path.contains("cert")
            {
                return true;
            }

            true
        } else {
            false
        }
    }

    /// Fetch CRL from a distribution point URL
    pub async fn fetch_crl(&mut self, distribution_point: &str) -> Result<CrlEntry, CrlError> {
        // Check if we have a cached CRL that's still valid
        if let Some(cached_crl) = self.crl_cache.get(distribution_point) {
            if cached_crl.is_valid() {
                debug!("Using cached CRL from {}", distribution_point);
                return Ok(cached_crl.clone());
            } else {
                debug!(
                    "Cached CRL from {} is expired, fetching new one ",
                    distribution_point
                );
            }
        }

        info!("Fetching CRL from: {}", distribution_point);

        // Validate URL
        let _url = Url::parse(distribution_point)
            .map_err(|_| CrlError::Custom(format!("Invalid CRL URL: {}", distribution_point)))?;

        // Fetch CRL with timeout
        let response = timeout(
            self.request_timeout,
            self.client.get(distribution_point).send(),
        )
        .await
        .map_err(|_| CrlError::Timeout)?
        .map_err(CrlError::Http)?;

        if !response.status().is_success() {
            return Err(CrlError::Custom(format!(
                "HTTP error {}: failed to fetch CRL from {}",
                response.status(),
                distribution_point
            )));
        }

        let crl_data = response.bytes().await.map_err(CrlError::Http)?.to_vec();

        // Parse CRL
        let crl_entry = CrlEntry::from_der(crl_data, distribution_point.to_string())?;

        // Cache the CRL
        self.crl_cache
            .insert(distribution_point.to_string(), crl_entry.clone());

        info!(
            "Successfully fetched and cached CRL from {}",
            distribution_point
        );
        Ok(crl_entry)
    }

    /// Check if a certificate is revoked by fetching and validating its CRLs
    pub async fn check_certificate_revocation(
        &mut self,
        cert: &X509Certificate<'_>,
        trust_store: &MemoryTrustStore,
    ) -> Result<bool, CrlError> {
        // Extract CRL distribution points
        let distribution_points = self.extract_crl_distribution_points(cert);

        if distribution_points.is_empty() {
            warn!("No CRL distribution points found in certificate ");
            return Err(CrlError::NoDistributionPoint);
        }

        // Try each distribution point
        for dp in &distribution_points {
            match self.fetch_crl(dp).await {
                Ok(crl_entry) => {
                    // Find the issuer certificate to verify CRL signature
                    let issuer_subject = format!("{}", cert.tbs_certificate.issuer);

                    match trust_store.get_cert_by_subject(&issuer_subject).await {
                        Ok(Some(issuer_entry)) => {
                            let issuer_cert = issuer_entry.parse()?;

                            // Verify CRL signature
                            if crl_entry.verify_signature(&issuer_cert)? {
                                // Check if certificate is revoked
                                let serial = cert.tbs_certificate.serial.to_bytes_be();
                                if crl_entry.is_certificate_revoked(&serial) {
                                    return Ok(true); // Certificate is revoked
                                }
                            } else {
                                warn!("CRL signature verification failed for {}", dp);
                            }
                        }
                        Ok(None) => {
                            warn!(
                                "Issuer certificate not found in trust store for CRL verification "
                            );
                        }
                        Err(e) => {
                            warn!("Error retrieving issuer certificate: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("{e}: {dp}");
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
    ) -> Result<bool, CrlError> {
        let cert = cert_entry.parse()?;

        match self.check_certificate_revocation(&cert, trust_store).await {
            Ok(is_revoked) => {
                if is_revoked {
                    info!("Certificate is revoked according to CRL ");
                    Ok(false) // Certificate is not valid
                } else {
                    info!("Certificate is not revoked according to CRL ");
                    Ok(true) // Certificate is valid
                }
            }
            Err(CrlError::NoDistributionPoint) => {
                if allow_fallback {
                    warn!("No CRL distribution points found, allowing certificate (fallback mode)");
                    Ok(true) // Allow certificate when no CRL is available
                } else {
                    warn!("No CRL distribution points found, rejecting certificate ");
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
                    warn!("CRL validation failed ({}), rejecting certificate ", e);
                    Err(e)
                }
            }
        }
    }

    /// Remove revoked certificates from trust store based on CRL
    pub async fn cleanup_revoked_certificates(
        &mut self,
        trust_store: &MemoryTrustStore,
    ) -> Result<usize, CrlError> {
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
                    debug!("Certificate is valid, keeping in trust store ");
                }
                Err(e) => {
                    // CRL check failed, log warning but don't remove certificate
                    warn!("{e}");
                }
            }
        }

        info!(
            "Removed {} revoked certificates from trust store ",
            removed_count
        );
        Ok(removed_count)
    }
}

impl Default for CrlManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_manager_creation() {
        let _manager = CrlManager::new();
        // Just test that creation doesn't panic
    }

    #[tokio::test]
    async fn test_invalid_url_handling() {
        let mut manager = CrlManager::new();
        let result = manager.fetch_crl("invalid").await;
        assert!(result.is_err());
    }
}
