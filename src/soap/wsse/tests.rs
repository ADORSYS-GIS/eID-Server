use crate::crypto::rsa::{RsaKeyPair, RsaKeySize, RsaPrivateKey};
use crate::soap::wsse::*;
use quick_xml::se::to_string as xml_to_string;

fn serialize_ws_security(ws_security: &WsSecurity) -> Result<String> {
    // Serialize the WsSecurity struct directly to match how it's done in the main module
    let security_xml = xml_to_string(ws_security).map_err(Error::from)?;
    Ok(security_xml)
}

fn create_test_soap_envelope(body_content: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                            xmlns:wsa="http://www.w3.org/2005/03/addressing">
                <soapenv:Header>
                    <wsa:MessageID>urn:uuid:test-message-id</wsa:MessageID>
                </soapenv:Header>
                <soapenv:Body>
                    {body_content}
                </soapenv:Body>
            </soapenv:Envelope>"#,
    )
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
        let envelope = include_str!("../../../test_data/eid/startPAOS.xml");

        let sign_config = SignConfig {
            private_key: key_pair.private_key().clone(),
            certificate: cert_der,
            timestamp_ttl: None,
        };

        let (ws_security, _) = sign_envelope(envelope, sign_config).unwrap();

        assert!(!ws_security.timestamp.id.is_empty());
        assert!(!ws_security.signature.signature_value.is_empty());
        assert_eq!(ws_security.signature.signed_info.references.len(), 2);
        assert!(ws_security.timestamp.validate().is_ok());

        // Verify references point to correct elements
        let timestamp_ref = &ws_security.signature.signed_info.references[0];
        let body_ref = &ws_security.signature.signed_info.references[1];

        assert!(timestamp_ref.uri.starts_with("#TS-"));
        assert_eq!(body_ref.uri, "#Body-");

        assert_eq!(timestamp_ref.digest_method.algorithm, algorithms::SHA256);
        assert_eq!(body_ref.digest_method.algorithm, algorithms::SHA256);

        assert!(timestamp_ref.transforms.is_some());
        assert!(body_ref.transforms.is_some());
    }
}

#[test]
fn test_signature_with_empty_body() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();

    let envelope = create_test_soap_envelope("<empty/>");

    let sign_config = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der,
        timestamp_ttl: Some(300),
    };

    let (ws_security, _) = sign_envelope(envelope, sign_config).unwrap();

    // Should still work with empty body
    assert!(!ws_security.signature.signature_value.is_empty());
    assert_eq!(ws_security.signature.signed_info.references.len(), 2);
}

#[test]
fn test_signature_reference_structure() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let envelope = create_test_soap_envelope("<test>Reference test</test>");

    let sign_config = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der,
        timestamp_ttl: Some(300),
    };

    let (ws_security, _) = sign_envelope(envelope, sign_config).unwrap();

    assert_eq!(ws_security.signature.signed_info.references.len(), 2);

    for reference in &ws_security.signature.signed_info.references {
        assert!(reference.uri.starts_with('#'));

        // Check transforms
        assert!(reference.transforms.is_some());
        let transforms = reference.transforms.as_ref().unwrap();
        assert_eq!(transforms.transform.len(), 1);
        assert_eq!(
            transforms.transform[0].algorithm,
            algorithms::EXCLUSIVE_C14N
        );

        assert_eq!(reference.digest_method.algorithm, algorithms::SHA256);
        assert!(!reference.digest_value.is_empty());
    }
}

#[test]
fn test_signature_with_invalid_xml() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();

    // Invalid XML - unclosed tag
    let invalid_envelope = r#"<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Body>
                <test>Unclosed tag
            </soapenv:Body>
        </soapenv:Envelope>"#;

    let sign_config = SignConfig {
        private_key: key_pair.private_key().clone(),
        certificate: cert_der,
        timestamp_ttl: Some(300),
    };

    let result = sign_envelope(invalid_envelope, sign_config);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_signature_verification() {
    use crate::pki::truststore::{MemoryTrustStore, TrustStore};
    use tempfile::TempDir;

    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let key_der = include_bytes!("../../../test_certs/identity/x509_key.der");
    let private_key = RsaPrivateKey::from_der(key_der).unwrap();
    let envelope = create_test_soap_envelope("<test>Integration test</test>");

    // Create a trust store and add the certificate
    let temp_dir = TempDir::new().unwrap();
    let truststore = MemoryTrustStore::new(temp_dir.path()).await.unwrap();
    truststore.add_certs([cert_der.clone()]).await.unwrap();

    let sign_config = SignConfig {
        private_key,
        certificate: cert_der,
        timestamp_ttl: Some(300), // Use a fixed TTL for reproducible results
    };

    // Create a signed envelope - sign_envelope returns the modified envelope with body ID added
    let (ws_security, modified_envelope) = sign_envelope(envelope, sign_config).unwrap();

    // Serialize WS-Security header content
    let ws_security_xml = serialize_ws_security(&ws_security).unwrap();

    // Build the complete SOAP envelope with the WS-Security header
    let signed_envelope = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                            xmlns:wsa="http://www.w3.org/2005/03/addressing"
                            xmlns:wsse="{}"
                            xmlns:wsu="{}"
                            xmlns:ds="{}">
                <soapenv:Header>
                    <wsa:MessageID>urn:uuid:test-message-id</wsa:MessageID>
                    <wsse:Security>
                        {}
                    </wsse:Security>
                </soapenv:Header>
                {}
            </soapenv:Envelope>"#,
        ns::WSSE,
        ns::WSU,
        ns::DS,
        ws_security_xml,
        &modified_envelope[modified_envelope.find("<soapenv:Body").unwrap_or(0)..]
    );

    // Verify the signature - this should succeed
    let result = verify_envelope(&signed_envelope, truststore).await;
    if let Err(e) = &result {
        println!("Verification error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Verification failed: {}",
        result.unwrap_err()
    );
}

#[test]
fn test_signature_uniqueness() {
    let key_pair = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let cert_der = include_bytes!("../../../test_certs/identity/x509.der").to_vec();
    let envelope = create_test_soap_envelope("<test>Uniqueness test</test>");

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

    let (ws_security1, _) = sign_envelope(&envelope, sign_config1).unwrap();
    let (ws_security2, _) = sign_envelope(envelope, sign_config2).unwrap();

    // Timestamps should be different (different IDs and times)
    assert_ne!(ws_security1.timestamp.id, ws_security2.timestamp.id);
    assert_ne!(
        ws_security1.timestamp.created,
        ws_security2.timestamp.created
    );
    assert_ne!(
        ws_security1.timestamp.expires,
        ws_security2.timestamp.expires
    );

    // Signature values should be different (different timestamps)
    assert_ne!(
        ws_security1.signature.signature_value,
        ws_security2.signature.signature_value
    );
}
