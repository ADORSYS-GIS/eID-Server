use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509Builder, X509Name, X509NameBuilder};

/// Helper function to generate test certificates.
pub fn generate_test_certificates() -> TestCertificates {
    let (ca_cert, ca_key) = generate_ca_certificate();
    let (server_cert, server_key) = generate_leaf_certificate(&ca_cert, &ca_key);

    TestCertificates {
        server_cert,
        server_key,
        ca_cert: ca_cert.to_pem().unwrap(),
    }
}

#[derive(Debug, Clone)]
pub struct TestCertificates {
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

pub fn generate_ca_certificate() -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key_pair = PKey::from_rsa(rsa).unwrap();

    let mut cert_builder = X509Builder::new().unwrap();

    cert_builder.set_version(2).unwrap();

    let serial_number = generate_serial_number();
    cert_builder.set_serial_number(&serial_number).unwrap();

    let subject_name = create_x509_name(&[
        ("C", "CM"),
        ("L", "Douala"),
        ("O", "Test Organization"),
        ("OU", "Test CA"),
        ("CN", "Test Root CA"),
    ])
    .unwrap();
    cert_builder.set_subject_name(&subject_name).unwrap();
    cert_builder.set_issuer_name(&subject_name).unwrap();

    cert_builder.set_pubkey(&key_pair).unwrap();

    // Set validity period (1 year)
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    // Add extensions for CA certificate
    cert_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();

    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();

    cert_builder
        .sign(&key_pair, MessageDigest::sha256())
        .unwrap();

    (cert_builder.build(), key_pair)
}

pub fn generate_leaf_certificate(ca_cert: &X509, ca_key: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key_pair = PKey::from_rsa(rsa).unwrap();

    let mut cert_builder = X509Builder::new().unwrap();

    cert_builder.set_version(2).unwrap();

    let serial_number = generate_serial_number();
    cert_builder.set_serial_number(&serial_number).unwrap();

    let subject_name = create_x509_name(&[
        ("C", "CM"),
        ("L", "Yaounde"),
        ("O", "Test"),
        ("CN", "localhost"),
    ])
    .unwrap();
    cert_builder.set_subject_name(&subject_name).unwrap();
    // Set issuer name (CA)
    cert_builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();

    cert_builder.set_pubkey(&key_pair).unwrap();

    // Set validity period (1 year)
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    cert_builder
        .append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();

    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();

    // Add Subject Alternative Names
    cert_builder
        .append_extension(
            SubjectAlternativeName::new()
                .dns("localhost")
                .dns("127.0.0.1")
                .ip("127.0.0.1")
                .build(&cert_builder.x509v3_context(Some(ca_cert), None))
                .unwrap(),
        )
        .unwrap();

    // Sign with CA private key
    cert_builder.sign(ca_key, MessageDigest::sha256()).unwrap();

    (
        cert_builder.build().to_pem().unwrap(),
        key_pair.private_key_to_pem_pkcs8().unwrap(),
    )
}

fn generate_serial_number() -> Asn1Integer {
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    serial.to_asn1_integer().unwrap()
}

fn create_x509_name(entries: &[(&str, &str)]) -> Result<X509Name, openssl::error::ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    for (key, value) in entries {
        name_builder.append_entry_by_text(key, value)?;
    }
    Ok(name_builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_certificates() {
        let TestCertificates {
            server_cert,
            server_key,
            ca_cert,
        } = generate_test_certificates();

        // Verify certificates can be parsed
        assert!(X509::from_pem(&server_cert).is_ok());
        assert!(PKey::private_key_from_pem(&server_key).is_ok());
        assert!(X509::from_pem(&ca_cert).is_ok());
    }
}
