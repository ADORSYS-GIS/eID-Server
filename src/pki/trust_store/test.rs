use base64::{Engine as _, engine::general_purpose};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::{TrustStore, error::TrustStoreError, memory::MemoryTrustStore};

#[tokio::test]
async fn test_add_invalid_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let invalid_der = vec![0x01, 0x02, 0x03];

    let result = trust_store.add_certificate(invalid_der).await;
    assert!(matches!(
        result,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Verify no certificate was added
    let cert = trust_store
        .certificate("invalid_cert".as_bytes())
        .await
        .unwrap();
    assert!(cert.is_none());
}

#[tokio::test]
async fn test_add_valid_certificate_der() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();

    // Should successfully add valid certificate
    assert!(
        trust_store
            .add_certificate(der_bytes.clone())
            .await
            .unwrap()
    );

    // Should be able to retrieve the certificate by its DER bytes
    let retrieved = trust_store
        .certificate(der_bytes.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved, der_bytes);

    // Should also be retrievable by serial number (requires parsing inside the test)
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();
    let retrieved_by_serial = trust_store
        .certificate(serial_number.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);
}

#[tokio::test]
async fn test_add_valid_certificate_pem() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();
    let pem_bytes = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        general_purpose::STANDARD.encode(der_bytes.clone())
    );

    // Should successfully add valid PEM certificate
    assert!(
        trust_store
            .add_certificate(pem_bytes.as_bytes())
            .await
            .unwrap()
    );

    // Should be able to retrieve the certificate (which will be DER)
    let retrieved = trust_store
        .certificate(der_bytes.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved, der_bytes);
}

#[tokio::test]
async fn test_add_duplicate_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();

    assert!(
        trust_store
            .add_certificate(der_bytes.clone())
            .await
            .unwrap()
    );
    assert!(!trust_store.add_certificate(der_bytes).await.unwrap());
}

#[tokio::test]
async fn test_remove_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();

    trust_store
        .add_certificate(der_bytes.clone())
        .await
        .unwrap();

    // Remove by DER bytes
    assert!(
        trust_store
            .remove_certificate(der_bytes.as_slice())
            .await
            .unwrap()
    );
    assert!(
        trust_store
            .certificate(der_bytes.as_slice())
            .await
            .unwrap()
            .is_none()
    );

    // Add again to test remove by serial
    trust_store
        .add_certificate(der_bytes.clone())
        .await
        .unwrap();
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();

    // Remove by serial number (needs to be converted to bytes for the trait method)
    assert!(
        trust_store
            .remove_certificate(serial_number.as_bytes())
            .await
            .unwrap()
    );
    assert!(
        trust_store
            .certificate(serial_number.as_bytes())
            .await
            .unwrap()
            .is_none()
    );

    // Try removing a non-existent certificate
    assert!(
        !trust_store
            .remove_certificate("nonexistent".as_bytes())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_get_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();

    trust_store
        .add_certificate(der_bytes.clone())
        .await
        .unwrap();

    // Retrieve by DER bytes
    let retrieved_by_der = trust_store
        .certificate(der_bytes.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_der, der_bytes);

    // Retrieve by serial number
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = x509_cert.tbs_certificate.serial.to_string();
    let retrieved_by_serial = trust_store
        .certificate(serial_number.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);

    // Try retrieving a non-existent certificate
    assert!(
        trust_store
            .certificate("nonexistent".as_bytes())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_validate_certificate_chain() {
    let mut trust_store = MemoryTrustStore::new();

    let root_ca_der = include_bytes!("../../../test_data/pki/root_csca.cer").to_vec();
    let link_ca_der = include_bytes!("../../../test_data/pki/link_csca.cer").to_vec();

    // Add root CA to trust store
    trust_store
        .add_certificate(root_ca_der.clone())
        .await
        .unwrap();
    // Add link CA to trust store
    trust_store
        .add_certificate(link_ca_der.clone())
        .await
        .unwrap();

    let valid_chain = vec![link_ca_der.clone(), root_ca_der.clone()];
    assert!(trust_store.validate(valid_chain.into_iter()).await.is_ok());

    // Invalid chain (empty)
    let empty_chain: Vec<Vec<u8>> = vec![];
    assert!(matches!(
        trust_store.validate(empty_chain.into_iter()).await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Invalid chain (corrupt cert)
    let mut invalid_der = root_ca_der.clone();
    invalid_der[0] = 0x00; // Corrupt a byte
    let invalid_chain_corrupt = vec![invalid_der.clone()];
    assert!(matches!(
        trust_store
            .validate(invalid_chain_corrupt.into_iter())
            .await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Validate a chain with a certificate not in the store
    // Remove link_ca to simulate missing cert
    assert!(
        trust_store
            .remove_certificate(link_ca_der.as_slice())
            .await
            .unwrap()
    );
    let chain_with_missing_link = vec![link_ca_der.clone(), root_ca_der.clone()];
    assert!(matches!(
        trust_store
            .validate(chain_with_missing_link.into_iter())
            .await,
        Err(TrustStoreError::CertificateNotFound(_))
    ));
}
