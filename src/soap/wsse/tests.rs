use crate::crypto::rsa::{RsaKeyPair, RsaKeySize, RsaPrivateKey};
use crate::soap::Envelope;
use crate::soap::wsse::*;

#[derive(Debug, Clone, Serialize)]
struct TestData {
    pub data: String,
}

fn create_test_soap_envelope(body_content: &str) -> Envelope<TestData> {
    let body = TestData {
        data: body_content.to_string(),
    };
    Envelope::new(body)
}

#[test]
fn test_signature_generation() {
    for key_size in [
        RsaKeySize::Rsa2048,
        RsaKeySize::Rsa3072,
        RsaKeySize::Rsa4096,
    ] {
        let key_pair = RsaKeyPair::generate(key_size).unwrap();
        let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
        let envelope = create_test_soap_envelope("test body");

        let sign_config = SignConfig {
            private_key: key_pair.private_key().clone(),
            certificate: cert_der,
            timestamp_ttl: None,
        };

        let signed_envelope = sign_envelope(envelope, sign_config).unwrap();

        // Verify the signed envelope contains expected elements
        assert!(signed_envelope.contains("wsse:Security"));
        assert!(signed_envelope.contains("ds:Signature"));
        assert!(signed_envelope.contains("wsu:Timestamp"));
        assert!(signed_envelope.contains("Body-"));
    }
}

#[test]
fn test_signature_reference_structure() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let envelope = create_test_soap_envelope("Reference test");

    let sign_config = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der,
        timestamp_ttl: Some(300),
    };

    let signed_envelope = sign_envelope(envelope, sign_config).unwrap();

    // Verify signature structure in the XML
    assert!(signed_envelope.contains("ds:SignedInfo"));
    assert!(signed_envelope.contains("ds:Reference"));
    assert!(signed_envelope.contains("ds:Transforms"));
    assert!(signed_envelope.contains("ds:Transform"));
    assert!(signed_envelope.contains(algorithms::EXCLUSIVE_C14N));
    assert!(signed_envelope.contains("ds:DigestMethod"));
    assert!(signed_envelope.contains(algorithms::SHA256));
    assert!(signed_envelope.contains("ds:DigestValue"));

    // Verify reference URIs
    assert!(signed_envelope.contains("#TS-"));
    assert!(signed_envelope.contains("#Body-"));
}

#[tokio::test]
async fn test_signature_verification() {
    use crate::pki::truststore::{MemoryTrustStore, TrustStore};
    use tempfile::TempDir;

    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let key_der = include_bytes!("../../../test_certs/identity/x509_key.der");
    let private_key = RsaPrivateKey::from_der(key_der).unwrap();
    let envelope = create_test_soap_envelope("Signature verification");

    // Create a trust store and add the certificate
    let temp_dir = TempDir::new().unwrap();
    let truststore = MemoryTrustStore::new(temp_dir.path()).await.unwrap();
    truststore.add_certs([cert_der.clone()]).await.unwrap();

    let sign_config = SignConfig {
        private_key,
        certificate: cert_der,
        timestamp_ttl: Some(300),
    };

    let signed_envelope = sign_envelope(envelope, sign_config).unwrap();

    let result = verify_envelope(&signed_envelope, &truststore).await;
    assert!(result.is_ok());
}

#[test]
fn test_signature_uniqueness() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let envelope = create_test_soap_envelope("Uniqueness test");

    let sign_config1 = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der.clone(),
        timestamp_ttl: None,
    };

    let sign_config2 = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der,
        timestamp_ttl: None,
    };

    let signed_envelope1 = sign_envelope(envelope.clone(), sign_config1).unwrap();
    let signed_envelope2 = sign_envelope(envelope, sign_config2).unwrap();

    // Timestamps should be different (different IDs and times)
    let ts_id1 = extract_timestamp_id(&signed_envelope1);
    let ts_id2 = extract_timestamp_id(&signed_envelope2);
    assert_ne!(ts_id1, ts_id2);

    // Signature values should be different (different timestamps)
    let sig1 = extract_signature_value(&signed_envelope1);
    let sig2 = extract_signature_value(&signed_envelope2);
    assert_ne!(sig1, sig2);
}

fn extract_timestamp_id(xml: &str) -> String {
    use regex::Regex;
    let re = Regex::new(r#"wsu:Id="([^"]+)""#).unwrap();
    re.captures(xml)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

fn extract_signature_value(xml: &str) -> String {
    use regex::Regex;
    let re = Regex::new(r#"<ds:SignatureValue>([^<]+)</ds:SignatureValue>"#).unwrap();
    re.captures(xml)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}
