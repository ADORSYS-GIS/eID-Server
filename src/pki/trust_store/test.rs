use super::TrustStore;
use super::in_memory::InMemoryTrustStore;

#[tokio::test]
async fn test_new_trust_store() {
    let trust_store = InMemoryTrustStore::new();
    assert_eq!(trust_store.count().await, 0);
    assert!(trust_store.list_certificate_names().await.is_empty());
}

#[tokio::test]
async fn test_add_invalid_certificate_graceful_rejection() {
    let mut trust_store = InMemoryTrustStore::new();
    let invalid_der = vec![0x01, 0x02, 0x03];

    // Should gracefully reject invalid certificate
    assert!(
        !trust_store
            .add_certificate_der("invalid_cert".to_string(), invalid_der)
            .await
    );
    assert_eq!(trust_store.count().await, 0);
}

#[tokio::test]
async fn test_add_invalid_pem_graceful_rejection() {
    let mut trust_store = InMemoryTrustStore::new();
    let invalid_pem = b"-----BEGIN CERTIFICATE-----\nInvalid PEM data\n-----END CERTIFICATE-----";

    // Should gracefully reject invalid PEM
    assert!(
        !trust_store
            .add_certificate_pem("invalid_cert".to_string(), invalid_pem)
            .await
    );
    assert_eq!(trust_store.count().await, 0);
}

#[tokio::test]
async fn test_remove_nonexistent_certificate() {
    let mut trust_store = InMemoryTrustStore::new();

    // Should return false for non-existent certificates
    assert!(!trust_store.remove_certificate_by_name("nonexistent").await);
    assert!(
        !trust_store
            .remove_certificate_by_serial("nonexistent")
            .await
    );
}

#[tokio::test]
async fn test_get_nonexistent_certificate() {
    let trust_store = InMemoryTrustStore::new();

    // Should return None for non-existent certificates
    assert!(
        trust_store
            .get_certificate_der_by_name("nonexistent")
            .await
            .is_none()
    );
    assert!(
        trust_store
            .get_certificate_der_by_serial("nonexistent")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_empty_trust_store_operations() {
    let mut trust_store = InMemoryTrustStore::new();

    // All operations on empty trust store should work without panicking
    assert_eq!(trust_store.count().await, 0);
    assert!(trust_store.list_certificate_names().await.is_empty());
    assert!(!trust_store.remove_certificate_by_name("test").await);
    assert!(!trust_store.remove_certificate_by_serial("123").await);
    assert!(
        trust_store
            .get_certificate_der_by_name("test")
            .await
            .is_none()
    );
    assert!(
        trust_store
            .get_certificate_der_by_serial("123")
            .await
            .is_none()
    );
}

// Integration tests with real test certificates
#[tokio::test]
async fn test_add_valid_certificate_der() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Read a real test certificate
    let mut file = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes = Vec::new();
    file.read_to_end(&mut der_bytes).await.unwrap();

    // Should successfully add valid certificate
    assert!(
        trust_store
            .add_certificate_der("test_cert".to_string(), der_bytes.clone())
            .await
    );
    assert_eq!(trust_store.count().await, 1);
    assert!(
        trust_store
            .list_certificate_names()
            .await
            .contains(&"test_cert".to_string())
    );

    // Should be able to retrieve the certificate
    let retrieved = trust_store
        .get_certificate_der_by_name("test_cert")
        .await
        .unwrap();
    assert_eq!(retrieved, der_bytes);
}

#[tokio::test]
async fn test_add_multiple_certificates() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Read first certificate
    let mut file1 = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes1 = Vec::new();
    file1.read_to_end(&mut der_bytes1).await.unwrap();

    // Read second certificate
    let mut file2 = File::open("test_data/pki/Link-[CA]_TEST_csca-germany-0008-04f0.cer")
        .await
        .unwrap();
    let mut der_bytes2 = Vec::new();
    file2.read_to_end(&mut der_bytes2).await.unwrap();

    // Add both certificates
    assert!(
        trust_store
            .add_certificate_der("cert1".to_string(), der_bytes1.clone())
            .await
    );
    assert!(
        trust_store
            .add_certificate_der("cert2".to_string(), der_bytes2.clone())
            .await
    );

    assert_eq!(trust_store.count().await, 2);
    let cert_names = trust_store.list_certificate_names().await;
    assert!(cert_names.contains(&"cert1".to_string()));
    assert!(cert_names.contains(&"cert2".to_string()));

    // Verify both can be retrieved
    assert!(
        trust_store
            .get_certificate_der_by_name("cert1")
            .await
            .is_some()
    );
    assert!(
        trust_store
            .get_certificate_der_by_name("cert2")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn test_remove_certificate_by_name() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Add a certificate
    let mut file = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes = Vec::new();
    file.read_to_end(&mut der_bytes).await.unwrap();

    assert!(
        trust_store
            .add_certificate_der("test_cert".to_string(), der_bytes)
            .await
    );
    assert_eq!(trust_store.count().await, 1);

    // Remove the certificate
    assert!(trust_store.remove_certificate_by_name("test_cert").await);
    assert_eq!(trust_store.count().await, 0);
    assert!(
        trust_store
            .get_certificate_der_by_name("test_cert")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_get_certificate_by_serial_number() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Add a certificate
    let mut file = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes = Vec::new();
    file.read_to_end(&mut der_bytes).await.unwrap();

    assert!(
        trust_store
            .add_certificate_der("test_cert".to_string(), der_bytes.clone())
            .await
    );

    // Parse the certificate to get its serial number
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();

    // Should be able to retrieve by serial number
    let retrieved = trust_store
        .get_certificate_der_by_serial(&serial_number)
        .await
        .unwrap();
    assert_eq!(retrieved, der_bytes);
}

#[tokio::test]
async fn test_remove_certificate_by_serial() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Add a certificate
    let mut file = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes = Vec::new();
    file.read_to_end(&mut der_bytes).await.unwrap();

    assert!(
        trust_store
            .add_certificate_der("test_cert".to_string(), der_bytes.clone())
            .await
    );

    // Parse the certificate to get its serial number
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();

    // Remove by serial number
    assert!(
        trust_store
            .remove_certificate_by_serial(&serial_number)
            .await
    );
    assert_eq!(trust_store.count().await, 0);
    assert!(
        trust_store
            .get_certificate_der_by_name("test_cert")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_duplicate_certificate_names() {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut trust_store = InMemoryTrustStore::new();

    // Add first certificate
    let mut file1 = File::open("test_data/pki/[ROOT-CA]_Test-CSCA08.cer")
        .await
        .unwrap();
    let mut der_bytes1 = Vec::new();
    file1.read_to_end(&mut der_bytes1).await.unwrap();

    // Add second certificate
    let mut file2 = File::open("test_data/pki/Link-[CA]_TEST_csca-germany-0008-04f0.cer")
        .await
        .unwrap();
    let mut der_bytes2 = Vec::new();
    file2.read_to_end(&mut der_bytes2).await.unwrap();

    // Add both with same name - second should overwrite first
    assert!(
        trust_store
            .add_certificate_der("same_name".to_string(), der_bytes1)
            .await
    );
    assert!(
        trust_store
            .add_certificate_der("same_name".to_string(), der_bytes2.clone())
            .await
    );

    // Should still have only 1 certificate (the second one)
    assert_eq!(trust_store.count().await, 1);

    // Retrieved certificate should be the second one
    let retrieved = trust_store
        .get_certificate_der_by_name("same_name")
        .await
        .unwrap();
    assert_eq!(retrieved, der_bytes2);
}
