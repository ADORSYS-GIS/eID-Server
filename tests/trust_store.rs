use chrono::{Duration, NaiveDateTime, Utc};
use eid_server::pki::trust_store::updater::MockMasterListFetcher;
use eid_server::pki::trust_store::{
    certificate_manager::CertificateManager,
    cleaner::CertificateCleaner,
    error::TrustStoreError,
    models::CSCAPublicKeyInfo,
    persistence::{FileTrustStoreRepository, TrustStoreRepository},
    updater::MasterListUpdater,
};
use mockall::predicate::*;
use pem::Pem;
use std::{collections::HashMap, path::PathBuf};
use tokio::fs::{self, File};
use tokio::io::AsyncReadExt;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;
use x509_parser::prelude::{FromDer, X509Certificate};

// A fixed key for testing purposes. In a real application, this should be securely managed.
const TEST_ENCRYPTION_KEY: [u8; 32] = *b"testkeyforrusttruststorepurposes";

// Helper function to create a dummy CSCAPublicKeyInfo
fn create_dummy_cert(ski: &str, days_valid: i64) -> CSCAPublicKeyInfo {
    let now = Utc::now();
    CSCAPublicKeyInfo {
        subject_key_identifier: ski.to_string(),
        certificate_pem: format!(
            "-----BEGIN CERTIFICATE-----\nTEST_{}\n-----END CERTIFICATE-----",
            ski
        ),
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

    let (_, x509) =
        X509Certificate::from_der(&der_bytes).expect("Failed to parse X.509 certificate");

    // Extract Subject Key Identifier (SKI) - crucial for map key
    let ski = x509
        .extensions()
        .iter()
        .find_map(|ext| {
            if ext.oid == OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
                // Use the imported OID constant
                Some(hex::encode(ext.value))
            } else {
                None
            }
        })
        .expect("Subject Key Identifier not found in certificate extensions");

    // Convert DER bytes to PEM format for storage (clone der_bytes for Pem::new)
    let pem = pem::encode(&Pem::new("CERTIFICATE", der_bytes.clone()));

    // Parse ASN1Time to NaiveDateTime and then to DateTime<Utc>
    let not_before = NaiveDateTime::parse_from_str(
        &x509.tbs_certificate.validity.not_before.to_string(),
        "%b %_d %H:%M:%S %Y %z",
    )
    .unwrap();
    let not_after = NaiveDateTime::parse_from_str(
        &x509.tbs_certificate.validity.not_after.to_string(),
        "%b %_d %H:%M:%S %Y %z",
    )
    .unwrap();

    CSCAPublicKeyInfo {
        subject_key_identifier: ski,
        certificate_pem: pem,
        not_before: chrono::DateTime::<Utc>::from_naive_utc_and_offset(not_before, Utc),
        not_after: chrono::DateTime::<Utc>::from_naive_utc_and_offset(not_after, Utc),
        issuer_common_name: Some(x509.tbs_certificate.issuer.to_string()),
        subject_common_name: Some(x509.tbs_certificate.subject.to_string()),
    }
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
    manager.add_certificate(cert1.clone());

    assert_eq!(manager.get_certificate("ski1"), Some(cert1));
    assert!(manager.get_certificate("nonexistent").is_none());

    let cert2 = create_dummy_cert("ski1", 20);
    manager.add_certificate(cert2.clone());
    assert_eq!(manager.get_certificate("ski1"), Some(cert2));
}

#[tokio::test]
async fn test_certificate_manager_remove() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1 = create_dummy_cert("ski1", 10);
    manager.add_certificate(cert1.clone());

    assert!(manager.remove_certificate("ski1").is_some());
    assert!(manager.get_certificate("ski1").is_none());
    assert!(manager.remove_certificate("nonexistent").is_none());
}

#[tokio::test]
async fn test_certificate_manager_list() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cert1 = create_dummy_cert("ski1", 10);
    let cert2 = create_dummy_cert("ski2", 20);
    manager.add_certificate(cert1.clone());
    manager.add_certificate(cert2.clone());

    let listed_certs = manager.list_certificates();
    assert_eq!(listed_certs.len(), 2);
    assert!(listed_certs.contains(&cert1));
    assert!(listed_certs.contains(&cert2));
}

#[tokio::test]
async fn test_certificate_manager_clear() {
    let mut manager = CertificateManager::new(HashMap::new());
    manager.add_certificate(create_dummy_cert("ski1", 10));
    manager.clear_certificates();
    assert!(manager.list_certificates().is_empty());
}

#[tokio::test]
async fn test_file_trust_store_repository_empty_file() {
    let test_file = PathBuf::from("test_empty_trust_store.json");
    // Ensure the file exists before attempting to remove it at the end of the test.
    // We explicitly don't create it here to test the empty file scenario.

    let repo = FileTrustStoreRepository::new(test_file.clone(), TEST_ENCRYPTION_KEY);
    let certificates = repo.load_certificates().await.unwrap();
    assert!(certificates.is_empty());

    // Clean up only if the file was created (which it wouldn't be for an empty store load)
    // If we're testing an empty file, it shouldn't be created by load_certificates
    if test_file.exists() {
        fs::remove_file(&test_file).await.unwrap();
    }
}

#[tokio::test]
async fn test_file_trust_store_repository_save_and_load() {
    let test_file = PathBuf::from("test_save_load_trust_store.json");
    if test_file.exists() {
        fs::remove_file(&test_file).await.unwrap();
    }

    let repo = FileTrustStoreRepository::new(test_file.clone(), TEST_ENCRYPTION_KEY);
    let mut certs_to_save = HashMap::new();
    let real_cert = read_and_parse_cert("test_data/[ROOT-CA]_Test-CSCA08.cer").await;
    certs_to_save.insert(real_cert.subject_key_identifier.clone(), real_cert.clone());

    repo.save_certificates(&certs_to_save).await.unwrap();

    let loaded_certs = repo.load_certificates().await.unwrap();
    assert_eq!(loaded_certs.len(), 1);
    assert_eq!(
        loaded_certs.get(&real_cert.subject_key_identifier),
        Some(&real_cert)
    );

    fs::remove_file(&test_file).await.unwrap();
}

#[tokio::test]
async fn test_file_trust_store_repository_invalid_data() {
    let test_file = PathBuf::from("test_invalid_trust_store.json");
    if test_file.exists() {
        fs::remove_file(&test_file).await.unwrap();
    }
    fs::write(&test_file, "{invalid json}").await.unwrap();

    let repo = FileTrustStoreRepository::new(test_file.clone(), TEST_ENCRYPTION_KEY);
    let result = repo.load_certificates().await;
    assert!(result.is_err());
    if let Err(TrustStoreError::DecryptionError(_)) = result {
        // Correct error type
    } else {
        panic!("Expected DecryptionError, got {:?}", result);
    }

    fs::remove_file(&test_file).await.unwrap();
}

#[tokio::test]
async fn test_master_list_updater_success() {
    let mut mock_fetcher = MockMasterListFetcher::new();

    // Use a real certificate from test_data that should have an SKI
    let real_cert_info = read_and_parse_cert("test_data/[ROOT-CA]_Test-CSCA08.cer").await;
    let master_list_content = real_cert_info.certificate_pem.as_bytes().to_vec();

    mock_fetcher
        .expect_fetch_master_list()
        .times(1)
        .returning(move |_| {
            let content = master_list_content.clone();
            Box::pin(async move { Ok(content) })
        });

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
        listed_certs[0].certificate_pem,
        real_cert_info.certificate_pem
    );
}

#[tokio::test]
async fn test_master_list_updater_fetch_failure() {
    let mut mock_fetcher = MockMasterListFetcher::new();
    mock_fetcher
        .expect_fetch_master_list()
        .times(1)
        .returning(|_| {
            Box::pin(async move { Err(TrustStoreError::UpdateError("Network error".to_string())) })
        });

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
    manager.add_certificate(create_dummy_cert("ski1", 10)); // Valid for 10 days
    manager.add_certificate(create_dummy_cert("ski2", 5)); // Valid for 5 days

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert!(removed.is_empty());
    assert_eq!(manager.list_certificates().len(), 2);
}

#[tokio::test]
async fn test_certificate_cleaner_some_expired() {
    let mut manager = CertificateManager::new(HashMap::new());
    manager.add_certificate(create_dummy_cert("ski1", 10)); // Valid for 10 days
    manager.add_certificate(create_dummy_cert("ski2", -1)); // Expired yesterday
    manager.add_certificate(create_dummy_cert("ski3", 5)); // Valid for 5 days
    manager.add_certificate(create_dummy_cert("ski4", -10)); // Expired 10 days ago

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&"ski2".to_string()));
    assert!(removed.contains(&"ski4".to_string()));
    assert_eq!(manager.list_certificates().len(), 2);
    assert!(manager.get_certificate("ski1").is_some());
    assert!(manager.get_certificate("ski3").is_some());
}

#[tokio::test]
async fn test_certificate_cleaner_all_expired() {
    let mut manager = CertificateManager::new(HashMap::new());
    manager.add_certificate(create_dummy_cert("ski1", -1));
    manager.add_certificate(create_dummy_cert("ski2", -5));

    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert_eq!(removed.len(), 2);
    assert!(manager.list_certificates().is_empty());
}

#[tokio::test]
async fn test_certificate_cleaner_empty_manager() {
    let mut manager = CertificateManager::new(HashMap::new());
    let cleaner = CertificateCleaner::new();
    let removed = cleaner.cleanup_expired_certificates(&mut manager);
    assert!(removed.is_empty());
    assert!(manager.list_certificates().is_empty());
}
