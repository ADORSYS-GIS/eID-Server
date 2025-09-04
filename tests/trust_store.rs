use chrono::{Duration, Utc};
use eid_server::pki::trust_store::{
    certificate_manager::CertificateManager, error::TrustStoreError, models::CSCAPublicKeyInfo,
};
use mockall::predicate::*;
use std::collections::HashMap;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

// Trait for fetching the master list (e.g., from a URL)
#[async_trait::async_trait]
pub trait MasterListFetcher: Send + Sync {
    async fn fetch_master_list(&self, url: &str) -> Result<Vec<u8>, TrustStoreError>;
}

// Mock implementation of MasterListFetcher for testing
mockall::mock! {
    pub MasterListFetcher {}

    #[async_trait::async_trait]
    impl MasterListFetcher for MasterListFetcher {
        async fn fetch_master_list(&self, url: &str) -> Result<Vec<u8>, TrustStoreError>;
    }
}

pub struct MasterListUpdater {
    fetcher: Box<dyn MasterListFetcher>,
}

impl MasterListUpdater {
    pub fn new(fetcher: Box<dyn MasterListFetcher>) -> Self {
        Self { fetcher }
    }

    pub async fn update_from_master_list(
        &self,
        manager: &mut CertificateManager,
        master_list_url: &str,
    ) -> Result<(), TrustStoreError> {
        let master_list_content = self.fetcher.fetch_master_list(master_list_url).await?;

        let certificates = CSCAPublicKeyInfo::parse_der_certificates_from_bytes(
            &master_list_content,
        )
        .map_err(|e| {
            TrustStoreError::UpdateError(format!("Failed to parse master list content: {}", e))
        })?;

        if certificates.is_empty() {
            return Err(TrustStoreError::UpdateError(
                "No certificates found in master list".to_string(),
            ));
        }

        for cert_info in certificates {
            manager.add_certificate(cert_info)?;
        }
        Ok(())
    }
}

pub struct CertificateCleaner;

impl Default for CertificateCleaner {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateCleaner {
    pub fn new() -> Self {
        Self
    }

    pub fn cleanup_expired_certificates(&self, manager: &mut CertificateManager) -> Vec<String> {
        let now = Utc::now();
        let expired_skis: Vec<String> = manager
            .list_certificates()
            .into_iter()
            .filter(|cert| cert.not_after < now)
            .map(|cert| cert.subject_key_identifier)
            .collect();

        for ski in &expired_skis {
            let _ = manager.remove_certificate(ski);
        }
        expired_skis
    }
}

// Helper function to create a dummy CSCAPublicKeyInfo
fn create_dummy_cert(ski: &str, days_valid: i64) -> CSCAPublicKeyInfo {
    let now = Utc::now();
    CSCAPublicKeyInfo {
        subject_key_identifier: ski.to_string(),
        certificate_der: vec![0xDE, 0xAD, 0xBE, 0xEF], // Placeholder DER
        serial_number: format!("serial-{}", ski),      // Placeholder serial
        not_before: now - Duration::days(1),
        not_after: now + Duration::days(days_valid),
        issuer_common_name: Some(format!("Issuer {}", ski)),
        subject_common_name: Some(format!("Subject {}", ski)),
    }
}

// This simplified version extracts only the necessary parts for persistence testing.
async fn read_and_parse_cert(path: &str) -> CSCAPublicKeyInfo {
    let mut file = File::open(path)
        .await
        .expect("Failed to open certificate file");
    let mut der_bytes = Vec::new();
    file.read_to_end(&mut der_bytes)
        .await
        .expect("Failed to read certificate file");

    CSCAPublicKeyInfo::try_from_der_single(&der_bytes)
        .expect("Failed to parse X.509 certificate from file")
}

#[tokio::test]
async fn test_certificate_manager_new() {
    let certificates = HashMap::new();
    let manager = CertificateManager::new(certificates);
    assert!(manager.list_certificates().is_empty());
}

#[tokio::test]
async fn test_certificate_manager_add_and_get() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1 = create_dummy_cert("ski1", 10);
    let _ = manager.add_certificate(cert1.clone());

    assert_eq!(manager.get_certificate_by_ski("ski1"), Some(cert1));
    assert!(manager.get_certificate_by_ski("nonexistent").is_none());

    let cert2 = create_dummy_cert("ski1", 20);
    let _ = manager.add_certificate(cert2.clone());
    assert_eq!(manager.get_certificate_by_ski("ski1"), Some(cert2));
}

#[tokio::test]
async fn test_certificate_manager_remove() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1 = create_dummy_cert("ski1", 10);
    let _ = manager.add_certificate(cert1.clone());

    assert!(manager.remove_certificate("ski1").is_some());
    assert!(manager.get_certificate_by_ski("ski1").is_none());
    assert!(manager.remove_certificate("nonexistent").is_none());
}

#[tokio::test]
async fn test_certificate_manager_list() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1 = create_dummy_cert("ski1", 10);
    let cert2 = create_dummy_cert("ski2", 20);
    let _ = manager.add_certificate(cert1.clone());
    let _ = manager.add_certificate(cert2.clone());

    let listed_certs = manager.list_certificates();
    assert_eq!(listed_certs.len(), 2);
    assert!(listed_certs.contains(&cert1));
    assert!(listed_certs.contains(&cert2));
}

#[tokio::test]
async fn test_certificate_manager_clear() {
    let mut manager = CertificateManager::new(HashMap::new());
    let _ = manager.add_certificate(create_dummy_cert("ski1", 10));
    // manager.clear_certificates(); // Method removed. Test needs adjustment.
    assert!(manager.list_certificates().is_empty());
}

#[tokio::test]
async fn test_master_list_updater_success() {
    let mut mock_fetcher = MockMasterListFetcher::new();

    // Use a real certificate from test_data that should have an SKI
    let real_cert_info = read_and_parse_cert("test_data/[ROOT-CA]_Test-CSCA08.cer").await;
    let master_list_content = real_cert_info.certificate_der.clone();

    mock_fetcher
        .expect_fetch_master_list()
        .times(1)
        .returning(move |_| Ok(master_list_content.clone()));

    let updater = MasterListUpdater::new(Box::new(mock_fetcher));
    let mut manager = CertificateManager::new(HashMap::new());
    let master_list_url = "http://example.com/masterlist.pem";

    updater
        .update_from_master_list(&mut manager, master_list_url)
        .await
        .unwrap();

    // Check if the real certificate is added
    let listed_certs = manager.list_certificates();
    assert_eq!(listed_certs.len(), 1);
    assert_eq!(
        listed_certs[0].subject_key_identifier,
        real_cert_info.subject_key_identifier
    );
    assert_eq!(
        listed_certs[0].certificate_der,
        real_cert_info.certificate_der
    );
}

#[tokio::test]
async fn test_master_list_updater_fetch_failure() {
    let mut mock_fetcher = MockMasterListFetcher::new();
    mock_fetcher
        .expect_fetch_master_list()
        .times(1)
        .returning(|_| Err(TrustStoreError::UpdateError("Network error".to_string())));

    let updater = MasterListUpdater::new(Box::new(mock_fetcher));
    let mut manager = CertificateManager::new(HashMap::new());
    let master_list_url = "http://example.com/masterlist.pem";

    let result = updater
        .update_from_master_list(&mut manager, master_list_url)
        .await;
    assert!(result.is_err());
    if let Err(TrustStoreError::UpdateError(msg)) = result {
        assert!(msg.contains("Network error"));
    } else {
        panic!("Expected UpdateError, got {:?}", result);
    }
    assert!(manager.list_certificates().is_empty());
}

#[tokio::test]
async fn test_certificate_cleaner_no_expired() {
    let mut manager = CertificateManager::new(HashMap::new());
    let _ = manager.add_certificate(create_dummy_cert("ski1", 10));

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert!(removed.is_empty());
    assert_eq!(manager.list_certificates().len(), 2);
}

#[tokio::test]
async fn test_certificate_cleaner_some_expired() {
    let mut manager = CertificateManager::new(HashMap::new());

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&"ski2".to_string()));
    assert!(removed.contains(&"ski4".to_string()));
    assert_eq!(manager.list_certificates().len(), 2);
    assert!(manager.get_certificate_by_ski("ski1").is_some());
    assert!(manager.get_certificate_by_ski("ski3").is_some());
}

#[tokio::test]
async fn test_certificate_cleaner_all_expired() {
    let mut manager = CertificateManager::new(HashMap::new());

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 2);
    assert!(manager.list_certificates().is_empty());
}
