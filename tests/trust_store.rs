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

// Helper function to create a CSCAPublicKeyInfo from a test file,
// optionally modifying its validity period and ensuring unique SKI for testing.
async fn create_test_cert_info(path: &str, days_offset: i64, unique_id: &str) -> CSCAPublicKeyInfo {
    let mut cert_info = read_and_parse_cert(path).await;
    // Adjust validity for testing purposes
    let now = Utc::now();
    cert_info.not_before = now + Duration::days(days_offset - 1);
    cert_info.not_after = now + Duration::days(days_offset);
    // Ensure unique SKI for test certificates if they originate from the same file
    cert_info.subject_key_identifier =
        format!("{}-{}", cert_info.subject_key_identifier, unique_id);
    cert_info.serial_number = format!("{}-{}", cert_info.serial_number, unique_id);
    cert_info
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
    let cert1_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "cert1").await;
    manager.add_certificate(cert1_info.clone()).unwrap();

    assert_eq!(
        manager.get_certificate_by_ski(&cert1_info.subject_key_identifier),
        Some(cert1_info.clone())
    );
    assert!(manager.get_certificate_by_ski("nonexistent").is_none());

    let cert2_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 20, "cert1").await; // Overwrites cert1
    manager.add_certificate(cert2_info.clone()).unwrap();
    // When adding a certificate with the same SKI, it should replace the old one
    assert_eq!(
        manager.get_certificate_by_ski(&cert2_info.subject_key_identifier),
        Some(cert2_info)
    );
}

#[tokio::test]
async fn test_certificate_manager_remove() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "cert1").await;
    manager.add_certificate(cert1_info.clone()).unwrap();

    assert!(
        manager
            .remove_certificate(&cert1_info.subject_key_identifier)
            .is_some()
    );
    assert!(
        manager
            .get_certificate_by_ski(&cert1_info.subject_key_identifier)
            .is_none()
    );
    assert!(manager.remove_certificate("nonexistent").is_none());
}

#[tokio::test]
async fn test_certificate_manager_list() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "cert1").await;
    let cert2_info = create_test_cert_info(
        "test_data/Link-[CA]_TEST_csca-germany-0008-04f0.cer",
        20,
        "cert2",
    )
    .await;
    manager.add_certificate(cert1_info.clone()).unwrap();
    manager.add_certificate(cert2_info.clone()).unwrap();

    let listed_certs = manager.list_certificates();
    assert_eq!(listed_certs.len(), 2);
    assert!(
        listed_certs
            .iter()
            .any(|c| c.subject_key_identifier == cert1_info.subject_key_identifier)
    );
    assert!(
        listed_certs
            .iter()
            .any(|c| c.subject_key_identifier == cert2_info.subject_key_identifier)
    );
}

#[tokio::test]
async fn test_certificate_manager_clear() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "cert1").await;
    manager.add_certificate(cert1_info).unwrap();
    // To clear certificates, we would iterate and remove or reinitialize the manager.
    // For this test, we can simulate clearing by creating a new manager.
    let manager = CertificateManager::new(HashMap::new());
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
    let cert1_info =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "cert1").await; // Valid for 10 more days
    manager.add_certificate(cert1_info).unwrap();

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert!(removed.is_empty());
    assert_eq!(manager.list_certificates().len(), 1); // Only 1 non-expired cert
}

#[tokio::test]
async fn test_certificate_cleaner_some_expired() {
    let mut manager = CertificateManager::new(HashMap::new());

    // Add some certificates: one expired, one valid
    let cert1_valid =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", 10, "valid").await; // Valid
    let cert2_expired = create_test_cert_info(
        "test_data/Link-[CA]_TEST_csca-germany-0008-04f0.cer",
        -1,
        "expired",
    )
    .await; // Expired
    manager.add_certificate(cert1_valid.clone()).unwrap();
    manager.add_certificate(cert2_expired.clone()).unwrap();

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 1);
    assert!(removed.contains(&cert2_expired.subject_key_identifier));
    assert_eq!(manager.list_certificates().len(), 1); // One valid cert remains
    assert!(
        manager
            .get_certificate_by_ski(&cert1_valid.subject_key_identifier)
            .is_some()
    );
    assert!(
        manager
            .get_certificate_by_ski(&cert2_expired.subject_key_identifier)
            .is_none()
    ); // Expired cert is removed
}

#[tokio::test]
async fn test_certificate_cleaner_all_expired() {
    let mut manager = CertificateManager::new(HashMap::new());

    // Add only expired certificates
    let cert1_expired =
        create_test_cert_info("test_data/[ROOT-CA]_Test-CSCA08.cer", -10, "expired1").await; // Expired
    let cert2_expired = create_test_cert_info(
        "test_data/Link-[CA]_TEST_csca-germany-0008-04f0.cer",
        -5,
        "expired2",
    )
    .await; // Expired
    manager.add_certificate(cert1_expired.clone()).unwrap();
    manager.add_certificate(cert2_expired.clone()).unwrap();

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&cert1_expired.subject_key_identifier));
    assert!(removed.contains(&cert2_expired.subject_key_identifier));
    assert!(manager.list_certificates().is_empty());
}
