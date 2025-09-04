use std::borrow::Cow;
use std::fmt;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::{ASN1Time, FromDer, ParsedExtension, X509Certificate};
use x509_parser::x509::AttributeTypeAndValue;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CSCAPublicKeyInfo {
    pub subject_key_identifier: String,
    pub certificate_der: Vec<u8>,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer_common_name: Option<String>,
    pub subject_common_name: Option<String>,
}

pub fn asn1_time_to_chrono(
    asn1_time: ASN1Time,
) -> Result<DateTime<Utc>, crate::pki::trust_store::error::TrustStoreError> {
    let timestamp = asn1_time.timestamp();
    DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or_else(|| {
        crate::pki::trust_store::error::TrustStoreError::InvalidCertificate(format!(
            "Failed to convert ASN1Time timestamp {} to chrono::DateTime<Utc>",
            timestamp
        ))
    })
}

impl CSCAPublicKeyInfo {
    pub fn try_from_der_single(
        cert_der: &[u8],
    ) -> Result<Self, crate::pki::trust_store::error::TrustStoreError> {
        let (rem, x509_cert) = X509Certificate::from_der(cert_der).map_err(|e| {
            crate::pki::trust_store::error::TrustStoreError::InvalidCertificate(format!(
                "DER parsing failed: {}",
                e
            ))
        })?;

        if !rem.is_empty() {
            return Err(
                crate::pki::trust_store::error::TrustStoreError::InvalidCertificate(
                    "Certificate contains unparsed data after DER".to_string(),
                ),
            );
        }

        let subject_key_identifier = x509_cert
            .extensions()
            .iter()
            .find_map(|ext| {
                if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
                    if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
                        Some(hex::encode(ski.0))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        let serial_number = x509_cert.tbs_certificate.serial.to_string();
        let not_before = asn1_time_to_chrono(x509_cert.tbs_certificate.validity.not_before)?;
        let not_after = asn1_time_to_chrono(x509_cert.tbs_certificate.validity.not_after)?;
        let issuer_common_name = get_common_name(&x509_cert.tbs_certificate.issuer);
        let subject_common_name = get_common_name(&x509_cert.tbs_certificate.subject);

        Ok(CSCAPublicKeyInfo {
            subject_key_identifier,
            certificate_der: cert_der.to_vec(),
            serial_number,
            not_before,
            not_after,
            issuer_common_name,
            subject_common_name,
        })
    }

    pub fn parse_der_certificates_from_bytes(
        der_bytes: &[u8],
    ) -> Result<Vec<Self>, crate::pki::trust_store::error::TrustStoreError> {
        let mut certificates = Vec::new();
        let mut remaining = der_bytes;

        while !remaining.is_empty() {
            match X509Certificate::from_der(remaining) {
                Ok((rem, _x509_cert)) => {
                    // Create a slice for the current certificate's DER bytes
                    let cert_len = remaining.len() - rem.len();
                    let current_cert_der = &remaining[..cert_len];

                    let parsed_cert = Self::try_from_der_single(current_cert_der)?;
                    certificates.push(parsed_cert);
                    remaining = rem;
                }
                Err(e) => {
                    return Err(
                        crate::pki::trust_store::error::TrustStoreError::InvalidCertificate(
                            format!("Failed to parse a certificate from DER bytes: {}", e),
                        ),
                    );
                }
            }
        }
        Ok(certificates)
    }
}

impl fmt::Display for CSCAPublicKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CSCA Cert: SKI={}, Serial={}, Issuer CN={:?}, Subject CN={:?}, Valid from {} to {}",
            self.subject_key_identifier,
            self.serial_number,
            self.issuer_common_name,
            self.subject_common_name,
            self.not_before,
            self.not_after
        )
    }
}

static CN_OID: Lazy<Oid<'static>> = Lazy::new(|| Oid::new(Cow::Borrowed(&[2, 5, 4, 3])));

// Helper to extract Common Name from an X.509 Name
pub fn get_common_name(name: &x509_parser::x509::X509Name) -> Option<String> {
    name.iter_by_oid(&CN_OID)
        .filter_map(|attr_type_and_value: &AttributeTypeAndValue| {
            attr_type_and_value.as_str().map(String::from).ok()
        })
        .next()
}
