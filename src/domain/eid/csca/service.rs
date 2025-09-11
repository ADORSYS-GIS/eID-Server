use super::{
    CscaInfo, CscaLinkCertificate, CscaTrustStore, CscaValidationError, MasterList,
    MasterListParser,
};
use async_trait::async_trait;
use openssl::x509::X509;
use regex::Regex;
use reqwest::Client;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, error, info, warn};

/// CSCA validation service for managing Master Lists and trust stores
#[derive(Debug, Clone)]
pub struct CscaValidationService {
    /// Local trust store for trusted CSCA certificates
    trust_store: CscaTrustStore,
    /// Current Master List
    master_list: Option<MasterList>,
    /// HTTP client for downloading Master Lists
    http_client: Client,
}

impl CscaValidationService {
    /// Create a new CSCA validation service
    pub fn new() -> Result<Self, CscaValidationError> {
        let trust_store = CscaTrustStore::new()?;
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("eID-Server/0.1.0")
            .build()
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            trust_store,
            master_list: None,
            http_client,
        })
    }

    /// Load Master List from file
    pub async fn load_master_list_from_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
    ) -> Result<(), CscaValidationError> {
        let content = fs::read_to_string(file_path).await?;
        self.load_master_list_from_string(&content).await
    }

    /// Load Master List from string content
    pub async fn load_master_list_from_string(
        &mut self,
        content: &str,
    ) -> Result<(), CscaValidationError> {
        info!("Loading Master List from content");

        let master_list = MasterListParser::parse_auto(content)?;
        info!(
            "Parsed Master List version {} with {} countries",
            master_list.version,
            master_list.csca_certificates.len()
        );

        // Validate Master List is not expired
        if !master_list.is_valid() {
            warn!(
                "Master List has expired, next update was: {:?}",
                master_list.next_update
            );
        }

        self.master_list = Some(master_list);
        self.update_trust_store_from_master_list().await?;

        Ok(())
    }

    /// Fetch and load German Master List from BSI website
    pub async fn fetch_german_master_list(&mut self) -> Result<(), CscaValidationError> {
        const BSI_MASTER_LIST_URL: &str = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html";

        info!("Fetching German Master List from BSI website");

        // First, fetch the HTML page to find the actual Master List download link
        let html_response = self
            .http_client
            .get(BSI_MASTER_LIST_URL)
            .send()
            .await
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to fetch BSI page: {e}"))
            })?;

        if !html_response.status().is_success() {
            return Err(CscaValidationError::MasterListParse(format!(
                "BSI website returned error: {}",
                html_response.status()
            )));
        }

        let html_content = html_response.text().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to read BSI page content: {e}"))
        })?;

        // Parse HTML to find the Master List download link
        let download_url = self.extract_master_list_download_url(&html_content)?;

        info!("Found Master List download URL: {}", download_url);

        // Download the actual Master List file
        let master_list_response =
            self.http_client
                .get(&download_url)
                .send()
                .await
                .map_err(|e| {
                    CscaValidationError::MasterListParse(format!(
                        "Failed to download Master List: {e}"
                    ))
                })?;

        if !master_list_response.status().is_success() {
            return Err(CscaValidationError::MasterListParse(format!(
                "Master List download failed: {}",
                master_list_response.status()
            )));
        }

        let master_list_content = master_list_response.text().await.map_err(|e| {
            CscaValidationError::MasterListParse(
                format!("Failed to read Master List content: {e}",),
            )
        })?;

        info!("Downloaded Master List, parsing content");

        // Load the downloaded Master List
        self.load_master_list_from_string(&master_list_content)
            .await
    }

    /// Extract Master List download URL from BSI HTML page
    fn extract_master_list_download_url(
        &self,
        html_content: &str,
    ) -> Result<String, CscaValidationError> {
        // Look for common patterns in BSI download links
        let patterns = [
            r#"href="([^"]*\.ldif[^"]*)"#,
            r#"href="([^"]*\.xml[^"]*)"#,
            r#"href="([^"]*MasterList[^"]*)"#,
            r#"href="([^"]*CSCA[^"]*\.zip[^"]*)"#,
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(html_content) {
                    if let Some(url) = captures.get(1) {
                        let mut download_url = url.as_str().to_string();

                        // Convert relative URLs to absolute
                        if download_url.starts_with("/") {
                            download_url = format!("https://www.bsi.bund.de{download_url}");
                        } else if !download_url.starts_with("http") {
                            download_url = format!(
                                "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/{download_url}",
                            );
                        }

                        return Ok(download_url);
                    }
                }
            }
        }

        // Fallback: try common German Master List file names
        let fallback_urls = [
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.ldif",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.xml",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/MasterList.ldif",
        ];

        warn!("Could not parse download URL from HTML, trying fallback URLs");
        Ok(fallback_urls[0].to_string()) // Return first fallback
    }

    /// Update trust store with certificates from current Master List
    async fn update_trust_store_from_master_list(&mut self) -> Result<(), CscaValidationError> {
        let Some(ref master_list) = self.master_list else {
            return Err(CscaValidationError::MasterListParse(
                "No Master List loaded".to_string(),
            ));
        };

        info!("Updating trust store from Master List");
        let mut added_count = 0;
        let mut skipped_count = 0;

        // Add all valid CSCA certificates to trust store
        for (country_code, csca_list) in &master_list.csca_certificates {
            for csca in csca_list {
                if csca.is_valid() {
                    // Check if already exists in trust store
                    if !self
                        .trust_store
                        .trusted_certificates
                        .contains_key(&csca.fingerprint)
                    {
                        match self.trust_store.add_trusted_csca(csca.clone()) {
                            Ok(_) => {
                                debug!(
                                    "Added CSCA certificate for country {} to trust store",
                                    country_code
                                );
                                added_count += 1;
                            }
                            Err(e) => {
                                error!(
                                    "Failed to add CSCA certificate for country {}: {}",
                                    country_code, e
                                );
                            }
                        }
                    } else {
                        skipped_count += 1;
                    }
                } else {
                    warn!(
                        "Skipping expired CSCA certificate for country {}",
                        country_code
                    );
                    skipped_count += 1;
                }
            }
        }

        info!(
            "Trust store update complete: {} certificates added, {} skipped",
            added_count, skipped_count
        );
        Ok(())
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
    pub fn validate_link_certificates(&self) -> Result<Vec<ValidationResult>, CscaValidationError> {
        let Some(ref master_list) = self.master_list else {
            return Err(CscaValidationError::MasterListParse(
                "No Master List loaded".to_string(),
            ));
        };

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

    /// Get CSCA certificates for a specific country
    pub fn get_csca_for_country(&self, country_code: &str) -> Option<&Vec<CscaInfo>> {
        self.master_list
            .as_ref()
            .and_then(|ml| ml.get_csca_for_country(country_code))
    }

    /// Get all valid CSCA certificates for a country
    pub fn get_valid_csca_for_country(&self, country_code: &str) -> Vec<&CscaInfo> {
        self.master_list
            .as_ref()
            .map(|ml| ml.get_valid_csca_for_country(country_code))
            .unwrap_or_default()
    }

    /// Get current Master List
    pub fn get_master_list(&self) -> Option<&MasterList> {
        self.master_list.as_ref()
    }

    /// Get trust store statistics
    pub fn get_trust_store_stats(&self) -> TrustStoreStats {
        let trusted_certs = self.trust_store.get_all_trusted_csca();
        let valid_count = trusted_certs
            .values()
            .filter(|cert| cert.is_valid())
            .count();
        let expired_count = trusted_certs.len() - valid_count;

        let mut countries = HashMap::new();
        for cert in trusted_certs.values() {
            *countries.entry(cert.country_code.clone()).or_insert(0) += 1;
        }

        TrustStoreStats {
            total_certificates: trusted_certs.len(),
            valid_certificates: valid_count,
            expired_certificates: expired_count,
            countries_count: countries.len(),
            certificates_by_country: countries,
        }
    }

    /// Clean up expired certificates from trust store
    pub async fn cleanup_expired_certificates(&mut self) -> Result<usize, CscaValidationError> {
        info!("Cleaning up expired certificates from trust store");
        let removed_count = self.trust_store.cleanup_expired()?;
        info!(
            "Removed {} expired certificates from trust store",
            removed_count
        );
        Ok(removed_count)
    }

    /// Check if Master List needs updating
    pub fn needs_master_list_update(&self) -> bool {
        self.master_list
            .as_ref()
            .map(|ml| !ml.is_valid())
            .unwrap_or(true)
    }

    /// Automatically update German Master List from BSI if needed
    pub async fn auto_update_german_master_list(&mut self) -> Result<bool, CscaValidationError> {
        if !self.needs_master_list_update() {
            info!("Master List is still valid, no update needed");
            return Ok(false);
        }

        info!("Master List needs updating, fetching from BSI");

        // Try to fetch the new Master List with retry logic
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 3;

        while attempts < MAX_ATTEMPTS {
            attempts += 1;

            match self.fetch_german_master_list().await {
                Ok(_) => {
                    info!(
                        "Successfully updated Master List from BSI (attempt {})",
                        attempts
                    );
                    return Ok(true);
                }
                Err(e) => {
                    error!("Failed to fetch Master List (attempt {}): {}", attempts, e);
                    if attempts < MAX_ATTEMPTS {
                        warn!("Retrying in 30 seconds...");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Schedule periodic Master List updates from BSI
    pub async fn start_periodic_updates(
        &mut self,
        update_interval_hours: u64,
    ) -> Result<(), CscaValidationError> {
        info!(
            "Starting periodic Master List updates every {} hours",
            update_interval_hours
        );

        // Perform initial update
        if let Err(e) = self.auto_update_german_master_list().await {
            warn!("Initial Master List update failed: {}", e);
        }

        // Clone the service for the background task
        let mut service_clone = self.clone();
        let interval_duration = Duration::from_secs(update_interval_hours * 3600);

        // Spawn background task for periodic updates
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first tick since we already did the initial update
            interval.tick().await;

            loop {
                interval.tick().await;
                debug!("Running scheduled Master List update");

                match service_clone.auto_update_german_master_list().await {
                    Ok(_) => {
                        info!("Scheduled Master List update completed successfully");
                    }
                    Err(e) => {
                        error!("Scheduled Master List update failed: {}", e);
                    }
                }
            }
        });

        info!(
            "Periodic updates started (running every {} hours)",
            update_interval_hours
        );

        Ok(())
    }

    /// Get Master List update status and statistics
    pub fn get_update_status(&self) -> MasterListUpdateStatus {
        match &self.master_list {
            Some(ml) => MasterListUpdateStatus {
                has_master_list: true,
                version: Some(ml.version.clone()),
                issue_date: Some(ml.issue_date),
                next_update: Some(ml.next_update),
                is_valid: ml.is_valid(),
                countries_count: ml.csca_certificates.len(),
                total_certificates: ml.csca_certificates.values().map(|certs| certs.len()).sum(),
            },
            None => MasterListUpdateStatus {
                has_master_list: false,
                version: None,
                issue_date: None,
                next_update: None,
                is_valid: false,
                countries_count: 0,
                total_certificates: 0,
            },
        }
    }
}

impl Default for CscaValidationService {
    fn default() -> Self {
        Self::new().expect("Failed to create default CSCA validation service")
    }
}

/// Result of certificate validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub certificate_info: CscaInfo,
    pub is_valid: bool,
    pub error: Option<String>,
}

/// Trust store statistics
#[derive(Debug, Clone)]
pub struct TrustStoreStats {
    pub total_certificates: usize,
    pub valid_certificates: usize,
    pub expired_certificates: usize,
    pub countries_count: usize,
    pub certificates_by_country: HashMap<String, usize>,
}

/// Master List update status and information
#[derive(Debug, Clone)]
pub struct MasterListUpdateStatus {
    pub has_master_list: bool,
    pub version: Option<String>,
    pub issue_date: Option<time::OffsetDateTime>,
    pub next_update: Option<time::OffsetDateTime>,
    pub is_valid: bool,
    pub countries_count: usize,
    pub total_certificates: usize,
}

/// Trait for CSCA validation operations
#[async_trait]
pub trait CscaValidator {
    /// Load Master List from file
    async fn load_master_list(&mut self, file_path: &str) -> Result<(), CscaValidationError>;

    /// Validate a certificate
    fn validate_certificate(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError>;

    /// Get CSCA certificates for a country
    fn get_country_csca(&self, country_code: &str) -> Vec<CscaInfo>;
}

#[async_trait]
impl CscaValidator for CscaValidationService {
    async fn load_master_list(&mut self, file_path: &str) -> Result<(), CscaValidationError> {
        self.load_master_list_from_file(file_path).await
    }

    fn validate_certificate(&self, cert_der: &[u8]) -> Result<bool, CscaValidationError> {
        self.validate_certificate_der(cert_der)
    }

    fn get_country_csca(&self, country_code: &str) -> Vec<CscaInfo> {
        self.get_valid_csca_for_country(country_code)
            .into_iter()
            .cloned()
            .collect()
    }
}
