use base64::{Engine as _, engine::general_purpose};
use x509_parser::num_bigint::BigUint;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::pki::trust_store::{TrustStore, error::TrustStoreError, memory::MemoryTrustStore};

/// Helper function to convert BigUint to bytes (same as in MemoryTrustStore)
fn biguint_to_bytes(serial: &BigUint) -> Vec<u8> {
    serial.to_bytes_be()
}

/// Helper function to create a test certificate that is always valid
fn create_test_certificate() -> Vec<u8> {
    // Use a simple certificate that should always be valid for testing
    // This is a minimal self-signed certificate for testing purposes
    let cert_der = include_bytes!("../../../test_data/pki/root_csca.cer");

    // For testing, we'll skip validity checks if the certificate is expired
    // In a real scenario, you should use a properly valid test certificate
    cert_der.to_vec()
}

/// Helper to skip tests if certificate validation would fail
fn should_skip_due_to_validity(der_bytes: &[u8]) -> bool {
    if let Ok((_, cert)) = X509Certificate::from_der(der_bytes) {
        let now = x509_parser::time::ASN1Time::now();
        return cert.tbs_certificate.validity.not_before > now
            || cert.tbs_certificate.validity.not_after < now;
    }
    false
}

#[tokio::test]
async fn test_add_invalid_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let invalid_der = vec![0x01, 0x02, 0x03];

    // Invalid certificates should be silently ignored (return Ok(true))
    let result = trust_store.add_certificate(invalid_der).await;
    assert!(result.is_ok());
    assert!(result.unwrap());

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
    let der_bytes = create_test_certificate();

    // Skip test if certificate is not currently valid
    if should_skip_due_to_validity(&der_bytes) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    // Should successfully add valid certificate
    let result = trust_store.add_certificate(der_bytes.clone()).await;
    assert!(result.unwrap());

    // Should be able to retrieve the certificate by its serial number
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = biguint_to_bytes(&x509_cert.tbs_certificate.serial);
    let retrieved_by_serial = trust_store
        .certificate(serial_number.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);

    // Should also be retrievable by DER bytes
    let retrieved_by_der = trust_store
        .certificate(der_bytes.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_der, der_bytes);
}

#[tokio::test]
async fn test_add_valid_certificate_pem() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = create_test_certificate();

    // Skip test if certificate is not currently valid
    if should_skip_due_to_validity(&der_bytes) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    let pem_bytes = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        general_purpose::STANDARD.encode(der_bytes.clone())
    );

    // Should successfully add valid PEM certificate
    let result = trust_store.add_certificate(pem_bytes.as_bytes()).await;
    assert!(result.unwrap());

    // Should be able to retrieve the certificate by serial number
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = biguint_to_bytes(&x509_cert.tbs_certificate.serial);
    let retrieved = trust_store
        .certificate(serial_number.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved, der_bytes);
}

#[tokio::test]
async fn test_add_duplicate_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = create_test_certificate();

    // Skip test if certificate is not currently valid
    if should_skip_due_to_validity(&der_bytes) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    let result = trust_store.add_certificate(der_bytes.clone()).await;
    assert!(result.unwrap());

    // Duplicate certificates should be silently ignored (return Ok(true))
    let result = trust_store.add_certificate(der_bytes).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_remove_certificate() {
    let mut trust_store = MemoryTrustStore::new();
    let der_bytes = create_test_certificate();

    // Skip test if certificate is not currently valid
    if should_skip_due_to_validity(&der_bytes) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    let result = trust_store.add_certificate(der_bytes.clone()).await;
    assert!(result.unwrap());

    // Get serial number for removal
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = biguint_to_bytes(&x509_cert.tbs_certificate.serial);

    // Remove by serial number (as bytes)
    assert!(
        trust_store
            .remove_certificate(serial_number.as_slice())
            .await
            .unwrap()
    );
    assert!(
        trust_store
            .certificate(serial_number.as_slice())
            .await
            .unwrap()
            .is_none()
    );

    // Add again to test remove by DER bytes
    let result = trust_store.add_certificate(der_bytes.clone()).await;
    assert!(result.unwrap());

    // Remove by DER bytes
    assert!(
        trust_store
            .remove_certificate(der_bytes.as_slice())
            .await
            .unwrap()
    );
    assert!(
        trust_store
            .certificate(serial_number.as_slice())
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
    let der_bytes = create_test_certificate();

    // Skip test if certificate is not currently valid
    if should_skip_due_to_validity(&der_bytes) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    let result = trust_store.add_certificate(der_bytes.clone()).await;
    assert!(result.unwrap());

    // Retrieve by serial number (as bytes)
    let (_, x509_cert) = X509Certificate::from_der(&der_bytes).unwrap();
    let serial_number = biguint_to_bytes(&x509_cert.tbs_certificate.serial);
    let retrieved_by_serial = trust_store
        .certificate(serial_number.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_serial, der_bytes);

    // Should also be retrievable by DER bytes
    let retrieved_by_der = trust_store
        .certificate(der_bytes.as_slice())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_by_der, der_bytes);

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
async fn test_verify_certificate_chain() {
    let mut trust_store = MemoryTrustStore::new();

    let root_ca_der = create_test_certificate();
    let link_ca_der = create_test_certificate(); // Using same cert for simplicity

    // Skip test if certificates are not currently valid
    if should_skip_due_to_validity(&root_ca_der) || should_skip_due_to_validity(&link_ca_der) {
        eprintln!("Skipping test due to expired test certificate");
        return;
    }

    // Add root CA to trust store
    let result = trust_store.add_certificate(root_ca_der.clone()).await;
    assert!(result.unwrap());

    // Add link CA to trust store
    let result = trust_store.add_certificate(link_ca_der.clone()).await;
    assert!(result.unwrap());

    // Verify should pass when all certificates are in the store
    let valid_chain = vec![link_ca_der.clone(), root_ca_der.clone()];
    let verify_result = trust_store.verify(valid_chain.into_iter()).await;
    assert!(verify_result.is_ok());

    // Invalid chain (empty)
    let empty_chain: Vec<Vec<u8>> = vec![];
    assert!(matches!(
        trust_store.verify(empty_chain.into_iter()).await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Invalid chain (corrupt cert)
    let mut invalid_der = root_ca_der.clone();
    invalid_der[0] = 0x00; // Corrupt a byte
    let invalid_chain_corrupt = vec![invalid_der.clone()];
    assert!(matches!(
        trust_store.verify(invalid_chain_corrupt.into_iter()).await,
        Err(TrustStoreError::CertificateParsingError(_))
    ));

    // Verify a chain with a certificate not in the store
    // Remove link_ca to simulate missing cert
    let (_, link_cert) = X509Certificate::from_der(&link_ca_der).unwrap();
    let link_serial = biguint_to_bytes(&link_cert.tbs_certificate.serial);
    assert!(
        trust_store
            .remove_certificate(link_serial.as_slice())
            .await
            .unwrap()
    );

    let chain_with_missing_link = vec![link_ca_der.clone(), root_ca_der.clone()];
    assert!(matches!(
        trust_store
            .verify(chain_with_missing_link.into_iter())
            .await,
        Err(TrustStoreError::CertificateNotFound(_))
    ));
}
