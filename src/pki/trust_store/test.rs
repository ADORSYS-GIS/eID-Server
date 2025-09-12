#[allow(unused_imports)]
use base64::{Engine as _, engine::general_purpose};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
#[allow(unused_imports)]
use x509_parser::prelude::{FromDer, X509Certificate};

#[allow(unused_imports)]
use crate::pki::trust_store::{TrustStore, error::TrustStoreError, in_memory::InMemoryTrustStore};

/// Helper function to read certificate bytes from a file.
#[allow(dead_code)]
async fn read_cert_file(path: &str) -> Vec<u8> {
    let mut file = File::open(path)
        .await
        .unwrap_or_else(|e| panic!("Failed to open {}: {}", path, e));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await.unwrap();
    bytes
}

#[tokio::test]
async fn test_add_invalid_certificate() {
    let mut trust_store = InMemoryTrustStore::new();
    let invalid_der = vec![0x01, 0x02, 0x03];

    let result = trust_store
        .add_certificate("invalid_cert".to_string(), invalid_der)
        .await;
    assert!(matches!(
        result,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Verify no certificate was added
    let cert = trust_store.certificate("invalid_cert").await.unwrap();
    assert!(cert.is_none());
}

#[tokio::test]
async fn test_add_valid_certificate_der() {
    let mut trust_store = InMemoryTrustStore::new();
    let der_bytes = read_cert_file("test_data/pki/root_csca.cer").await;

    // Should successfully add valid certificate
    assert!(
        trust_store
            .add_certificate("test_cert".to_string(), der_bytes.clone())
            .await
            .unwrap()
    );

    // Should be able to retrieve the certificate
    let retrieved = trust_store.certificate("test_cert").await.unwrap().unwrap();
    assert_eq!(retrieved, der_bytes);

    // Should also be retrievable by serial number
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();
    let retrieved_by_serial = trust_store
        .certificate(&serial_number)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);
}

#[tokio::test]
async fn test_add_valid_certificate_pem() {
    let mut trust_store = InMemoryTrustStore::new();
    // Assuming you have a PEM encoded certificate for testing
    // For now, let's use the DER and encode it as PEM for the test
    let der_bytes = read_cert_file("test_data/pki/root_csca.cer").await;
    let pem_bytes = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        general_purpose::STANDARD.encode(der_bytes.clone())
    );

    // Should successfully add valid PEM certificate
    assert!(
        trust_store
            .add_certificate("test_pem_cert".to_string(), pem_bytes.as_bytes())
            .await
            .unwrap()
    );

    // Should be able to retrieve the certificate (which will be DER)
    let retrieved = trust_store
        .certificate("test_pem_cert")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved, der_bytes);
}

#[tokio::test]
async fn test_add_duplicate_certificate() {
    let mut trust_store = InMemoryTrustStore::new();
    let der_bytes = read_cert_file("test_data/pki/root_csca.cer").await;

    assert!(
        trust_store
            .add_certificate("cert_name".to_string(), der_bytes.clone())
            .await
            .unwrap()
    );
    assert!(
        !trust_store
            .add_certificate("cert_name".to_string(), der_bytes)
            .await
            .unwrap()
    ); // Duplicate name, should return false
}

#[tokio::test]
async fn test_remove_certificate() {
    let mut trust_store = InMemoryTrustStore::new();
    let der_bytes = read_cert_file("test_data/pki/root_csca.cer").await;
    let cert_name = "test_cert".to_string();

    trust_store
        .add_certificate(cert_name.clone(), der_bytes.clone())
        .await
        .unwrap();

    // Remove by name
    assert!(trust_store.remove_certificate(&cert_name).await.unwrap());
    assert!(trust_store.certificate(&cert_name).await.unwrap().is_none());

    // Add again to test remove by serial
    trust_store
        .add_certificate(cert_name.clone(), der_bytes.clone())
        .await
        .unwrap();
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();

    // Remove by serial number
    assert!(
        trust_store
            .remove_certificate(&serial_number)
            .await
            .unwrap()
    );
    assert!(
        trust_store
            .certificate(&serial_number)
            .await
            .unwrap()
            .is_none()
    );

    // Try removing a non-existent certificate
    assert!(!trust_store.remove_certificate("nonexistent").await.unwrap());
}

#[tokio::test]
async fn test_get_certificate() {
    let mut trust_store = InMemoryTrustStore::new();
    let der_bytes = read_cert_file("test_data/pki/root_csca.cer").await;
    let cert_name = "test_cert".to_string();

    trust_store
        .add_certificate(cert_name.clone(), der_bytes.clone())
        .await
        .unwrap();

    // Retrieve by name
    let retrieved_by_name = trust_store.certificate(&cert_name).await.unwrap().unwrap();
    assert_eq!(retrieved_by_name, der_bytes);

    // Retrieve by serial number
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();
    let retrieved_by_serial = trust_store
        .certificate(&serial_number)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);

    // Try retrieving a non-existent certificate
    assert!(
        trust_store
            .certificate("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_validate_certificate_chain() {
    let mut trust_store = InMemoryTrustStore::new();

    let root_ca_der = read_cert_file("test_data/pki/root_csca.cer").await;
    let link_ca_der = read_cert_file("test_data/pki/link_csca.cer").await;

    // Add root CA to trust store
    trust_store
        .add_certificate("root_ca".to_string(), root_ca_der.clone())
        .await
        .unwrap();
    // Add link CA to trust store
    trust_store
        .add_certificate("link_ca".to_string(), link_ca_der.clone())
        .await
        .unwrap();

    let valid_chain = vec![link_ca_der.clone(), root_ca_der.clone()];
    assert!(trust_store.validate(&valid_chain).await.is_ok());

    // Invalid chain (empty)
    let empty_chain = vec![];
    assert!(matches!(
        trust_store.validate(&empty_chain).await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Invalid chain (missing cert in store) - for this simple validation, it means not in store.
    let mut invalid_der = root_ca_der.clone();
    invalid_der[0] = 0x00; // Corrupt a byte
    let invalid_chain_corrupt = vec![invalid_der.clone()];
    assert!(matches!(
        trust_store.validate(&invalid_chain_corrupt).await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Validate a chain with a certificate not in the store
    let unknown_cert_der = read_cert_file("test_data/pki/root_csca.cer").await; // Re-using a known cert, but will treat as 'unknown'
    let (_, unknown_x509_cert) = X509Certificate::from_der(&unknown_cert_der).unwrap();
    let _unknown_serial = unknown_x509_cert.tbs_certificate.serial.to_string();

    // Remove link_ca to simulate missing cert
    trust_store.remove_certificate("link_ca").await.unwrap();
    let chain_with_missing_link = vec![link_ca_der.clone(), root_ca_der.clone()];
    assert!(matches!(
        trust_store.validate(&chain_with_missing_link).await,
        Err(TrustStoreError::CertificateNotFound(_))
    ));
}
