use chrono::{DateTime, Utc};
use reqwest::Client;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock},
    time::interval,
};
use tracing::{debug, error, info};
use x509_parser::parse_x509_certificate;

// Re-export public types and errors
pub use errors::{TrustStoreError, TrustStoreResult};
pub use types::{
    CertificateSource, CscaCertificate, MasterListInfo, TrustStoreConfig, TrustStoreData,
};

// Internal modules
mod errors;
mod master_list;
mod storage;
mod types;
mod validation;

use master_list::MasterListProcessor;
use storage::TrustStoreStorage;
use validation::{CertificateValidator, extract_country_code};

/// CSCA Trust Store Manager
pub struct CscaTrustStore {
    /// In-memory trust store data
    data: Arc<RwLock<TrustStoreData>>,
    /// Storage handler
    storage: TrustStoreStorage,
    /// Master list processor
    master_list_processor: MasterListProcessor,
    /// Mutex to prevent concurrent updates
    update_mutex: Arc<Mutex<()>>,
}

impl CscaTrustStore {
    /// Create a new CSCA trust store
    pub fn new(config: TrustStoreConfig) -> TrustStoreResult<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.download_timeout_seconds))
            .build()
            .map_err(TrustStoreError::NetworkError)?;

        let storage = TrustStoreStorage::new(config.clone());
        let master_list_processor = MasterListProcessor::new(http_client);

        let trust_store = Self {
            data: Arc::new(RwLock::new(TrustStoreData::default())),
            storage,
            master_list_processor,
            update_mutex: Arc::new(Mutex::new(())),
        };

        Ok(trust_store)
    }

    /// Load trust store from disk
    pub async fn load(&self) -> TrustStoreResult<()> {
        if let Some(store_data) = self.storage.load().await? {
            let mut data = self.data.write().await;
            *data = store_data;
        }
        Ok(())
    }

    /// Save trust store to disk atomically
    pub async fn save(&self) -> TrustStoreResult<()> {
        let data = self.data.read().await;
        self.storage.save(&data).await
    }

    /// Get a certificate by serial number
    pub async fn get_certificate(&self, serial_number: &str) -> Option<CscaCertificate> {
        let data = self.data.read().await;
        data.certificates.get(serial_number).cloned()
    }

    /// Get all certificates
    pub async fn get_all_certificates(&self) -> Vec<CscaCertificate> {
        let data = self.data.read().await;
        data.certificates.values().cloned().collect()
    }

    /// Get certificates by country code
    pub async fn get_certificates_by_country(&self, country_code: &str) -> Vec<CscaCertificate> {
        let data = self.data.read().await;
        data.certificates
            .values()
            .filter(|cert| cert.country_code == country_code)
            .cloned()
            .collect()
    }

    /// Check if a certificate is trusted
    pub async fn is_certificate_trusted(&self, certificate_der: &[u8]) -> TrustStoreResult<bool> {
        let (_, cert) = parse_x509_certificate(certificate_der).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!("Failed to parse certificate: {e}"))
        })?;

        let serial_number = format!("{:x}", cert.serial);
        let data = self.data.read().await;

        if let Some(trusted_cert) = data.certificates.get(&serial_number) {
            // Verify the certificate content matches
            Ok(trusted_cert.certificate_der == certificate_der)
        } else {
            Ok(false)
        }
    }

    /// Add a Link certificate to establish trust chain
    pub async fn add_link_certificate(
        &self,
        certificate_der: Vec<u8>,
        parent_serial: String,
    ) -> TrustStoreResult<()> {
        let _lock = self.update_mutex.lock().await;

        // Parse the certificate
        let cert_data = certificate_der.clone();
        let (_, cert) = parse_x509_certificate(&cert_data).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!("Failed to parse certificate: {e}"))
        })?;

        // Validate that the parent certificate exists and is trusted
        let data = self.data.read().await;
        if !data.certificates.contains_key(&parent_serial) {
            return Err(TrustStoreError::CertificateValidationError(format!(
                "Parent certificate with serial {parent_serial} not found in trust store",
            )));
        }
        drop(data);

        // Validate the Link certificate against its parent
        self.validate_link_certificate(&certificate_der, &parent_serial)
            .await?;

        let country_code = extract_country_code(&cert)?;
        let serial_number = format!("{:x}", cert.serial);
        let subject = cert.subject.to_string();
        let issuer = cert.issuer.to_string();
        let not_before = DateTime::from_timestamp(cert.validity.not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity.not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        let csca_cert = CscaCertificate {
            certificate_der,
            country_code,
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            added_at: Utc::now(),
            source: CertificateSource::LinkCertificate { parent_serial },
        };

        let mut data = self.data.write().await;
        data.certificates
            .insert(csca_cert.serial_number.clone(), csca_cert);
        data.last_updated = Utc::now();
        data.version += 1;

        drop(data);
        self.save().await?;

        info!(
            "Added Link certificate with serial: {}",
            cert.serial.to_string()
        );
        Ok(())
    }

    /// Validate a Link certificate against its parent certificate
    async fn validate_link_certificate(
        &self,
        link_cert_der: &[u8],
        parent_serial: &str,
    ) -> TrustStoreResult<()> {
        debug!(
            "Validating Link certificate against parent serial: {}",
            parent_serial
        );

        // Parse the Link certificate
        let (_, link_cert) = parse_x509_certificate(link_cert_der).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!(
                "Failed to parse Link certificate: {e}",
            ))
        })?;

        // Get the parent certificate
        let data = self.data.read().await;
        let parent_cert_data = data.certificates.get(parent_serial).ok_or_else(|| {
            TrustStoreError::CertificateValidationError(format!(
                "Parent certificate {parent_serial} not found",
            ))
        })?;

        let parent_cert_der = parent_cert_data.certificate_der.clone();
        drop(data);

        // Validate certificate chain: Link cert should be signed by parent
        CertificateValidator::validate_certificate_signature(link_cert_der, &parent_cert_der)?;

        // Validate certificate validity periods
        CertificateValidator::validate_certificate_validity(&link_cert)?;

        // Validate that this is indeed a Link certificate (has appropriate extensions)
        CertificateValidator::validate_link_certificate_extensions(&link_cert)?;

        debug!("Link certificate validation successful");
        Ok(())
    }

    /// Build and validate certificate chain from a certificate to a trusted root
    pub async fn validate_certificate_chain(
        &self,
        certificate_der: &[u8],
    ) -> TrustStoreResult<Vec<String>> {
        let mut chain = Vec::new();
        let mut current_der = certificate_der.to_vec();

        loop {
            let (_, current_cert) = parse_x509_certificate(&current_der).map_err(|e| {
                TrustStoreError::CertificateParsingError(format!(
                    "Failed to parse certificate: {e}",
                ))
            })?;

            let serial = format!("{:x}", current_cert.serial);
            chain.push(serial.clone());

            // Check if this certificate is directly trusted
            let data = self.data.read().await;
            if data.certificates.contains_key(&serial) {
                debug!("Found trusted certificate in chain: {}", serial);
                drop(data);
                return Ok(chain);
            }

            // Look for a parent certificate (issuer)
            let mut parent_found = false;
            let mut next_cert_der = Vec::new();

            for parent_cert_data in data.certificates.values() {
                let (_, parent_cert) =
                    match parse_x509_certificate(&parent_cert_data.certificate_der) {
                        Ok(result) => result,
                        Err(_) => continue,
                    };

                // Check if this parent could have signed the current certificate
                if current_cert.issuer() == parent_cert.subject() {
                    // Validate the signature
                    if CertificateValidator::validate_certificate_signature(
                        &current_der,
                        &parent_cert_data.certificate_der,
                    )
                    .is_ok()
                    {
                        next_cert_der = parent_cert_data.certificate_der.clone();
                        parent_found = true;
                        break;
                    }
                }
            }
            drop(data);

            if !parent_found {
                return Err(TrustStoreError::CertificateValidationError(
                    "Certificate chain validation failed: no trusted parent found".to_string(),
                ));
            }

            // Move to the next certificate in the chain
            current_der = next_cert_der;

            // Prevent infinite loops
            if chain.len() > 10 {
                return Err(TrustStoreError::CertificateValidationError(
                    "Certificate chain too long (possible loop)".to_string(),
                ));
            }
        }
    }

    /// Add a certificate manually
    pub async fn add_certificate_manual(
        &self,
        certificate_der: Vec<u8>,
        operator: String,
    ) -> TrustStoreResult<()> {
        let _lock = self.update_mutex.lock().await;

        let cert_data = certificate_der.clone();
        let (_, cert) = parse_x509_certificate(&cert_data).map_err(|e| {
            TrustStoreError::CertificateParsingError(format!("Failed to parse certificate: {e}"))
        })?;

        let country_code = extract_country_code(&cert)?;
        let serial_number = format!("{:x}", cert.serial);
        let subject = cert.subject.to_string();
        let issuer = cert.issuer.to_string();
        let not_before = DateTime::from_timestamp(cert.validity.not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity.not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        let csca_cert = CscaCertificate {
            certificate_der,
            country_code,
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            added_at: Utc::now(),
            source: CertificateSource::Manual { operator },
        };

        let mut data = self.data.write().await;
        data.certificates
            .insert(csca_cert.serial_number.clone(), csca_cert);
        data.last_updated = Utc::now();
        data.version += 1;

        drop(data);
        self.save().await?;

        info!(
            "Manually added certificate with serial: {}",
            cert.serial.to_string()
        );
        Ok(())
    }

    /// Remove expired certificates
    pub async fn remove_expired_certificates(&self) -> TrustStoreResult<usize> {
        let _lock = self.update_mutex.lock().await;
        let now = Utc::now();
        let mut removed_count = 0;

        let mut data = self.data.write().await;
        let mut to_remove = Vec::new();

        for (serial, cert) in &data.certificates {
            if cert.not_after < now {
                to_remove.push(serial.clone());
            }
        }

        for serial in to_remove {
            data.certificates.remove(&serial);
            removed_count += 1;
        }

        if removed_count > 0 {
            data.last_updated = Utc::now();
            data.version += 1;
            drop(data);
            self.save().await?;
            info!("Removed {} expired certificates", removed_count);
        }

        Ok(removed_count)
    }

    /// Start periodic refresh of master lists
    pub async fn start_periodic_refresh(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(
            self.storage.config().refresh_interval_seconds,
        ));

        loop {
            interval.tick().await;

            if let Err(e) = self.refresh_master_lists().await {
                error!("Failed to refresh master lists: {e}");
            }

            if self.storage.config().auto_remove_expired {
                if let Err(e) = self.remove_expired_certificates().await {
                    error!("Failed to remove expired certificates: {e}");
                }
            }
        }
    }

    /// Refresh all configured master lists
    pub async fn refresh_master_lists(&self) -> TrustStoreResult<()> {
        info!("Starting master list refresh");

        for url in &self.storage.config().master_list_urls {
            if let Err(e) = self.refresh_master_list(url).await {
                error!("Failed to refresh master list from {url}: {e}");
                // Continue with other URLs even if one fails
            }
        }

        Ok(())
    }

    /// Refresh a single master list
    async fn refresh_master_list(&self, url: &str) -> TrustStoreResult<()> {
        let (certificates, etag, content_hash) = self
            .master_list_processor
            .download_and_process_master_list(url)
            .await?;

        if certificates.is_empty() {
            return Ok(());
        }

        // Update trust store with new certificates
        self.update_certificates_from_master_list(certificates, url, etag, content_hash)
            .await?;

        info!("Successfully refreshed master list from: {url}");
        Ok(())
    }

    /// Update trust store with certificates from master list
    async fn update_certificates_from_master_list(
        &self,
        certificates: Vec<CscaCertificate>,
        url: &str,
        etag: Option<String>,
        content_hash: String,
    ) -> TrustStoreResult<()> {
        let _lock = self.update_mutex.lock().await;

        let mut data = self.data.write().await;
        let mut added_count = 0;

        for cert in certificates {
            if !data.certificates.contains_key(&cert.serial_number) {
                data.certificates.insert(cert.serial_number.clone(), cert);
                added_count += 1;
            }
        }

        // Update master list info
        let master_list_info = MasterListInfo {
            url: url.to_string(),
            last_downloaded: Utc::now(),
            etag: etag.clone(),
            content_hash: content_hash.clone(),
            certificate_count: added_count,
        };

        data.master_lists.insert(url.to_string(), master_list_info);
        data.last_updated = Utc::now();
        data.version += 1;

        drop(data);
        self.save().await?;

        info!(
            "Added {added_count} new certificates from master list: {url} (ETag: {etag:?}, Hash: {})",
            &content_hash[..8]
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_trust_store_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = TrustStoreConfig {
            store_path: temp_dir.path().join("test_store.json"),
            backup_dir: temp_dir.path().join("backups"),
            ..Default::default()
        };

        let trust_store = CscaTrustStore::new(config).unwrap();
        assert!(trust_store.get_all_certificates().await.is_empty());
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config = TrustStoreConfig {
            store_path: temp_dir.path().join("test_store.json"),
            backup_dir: temp_dir.path().join("backups"),
            ..Default::default()
        };

        let trust_store = CscaTrustStore::new(config).unwrap();

        // Save empty store
        trust_store.save().await.unwrap();

        // Load it back
        trust_store.load().await.unwrap();

        assert!(trust_store.get_all_certificates().await.is_empty());
    }
}
