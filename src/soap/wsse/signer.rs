use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::crypto::{HashAlg, rsa, rsa::RsaPrivateKey};
use crate::pki::truststore::CertificateEntry;
use crate::soap::wsse::timestamp::Timestamp;
use crate::soap::{Envelope, Header, wsse::*};

/// Configuration for signing SOAP messages
pub struct SignConfig {
    /// Private key for signing
    pub private_key: RsaPrivateKey,

    /// DER encoded X.509 certificate
    pub certificate: Vec<u8>,

    /// Timestamp TTL in seconds (default: 300)
    pub timestamp_ttl: Option<i64>,
}

/// Sign the SOAP envelope according to WS-Security policy.
pub fn sign_envelope<T: Serialize>(env: Envelope<T>, config: SignConfig) -> Result<String> {
    let unsigned_env = env.serialize_soap(false)?;
    let body_id = format!("Body-{}", uuid::Uuid::new_v4());
    let ws_security = sign_inner(&unsigned_env, &body_id, config)?;
    let header = Header {
        message_id: None,
        relates_to: None,
        security: Some(ws_security),
    };
    let security_env = env.with_header(header);
    let security_env_xml = security_env.serialize_soap(false)?;
    utils::add_body_id_to_envelope(&security_env_xml, &body_id)
}

/// Sign the envelope and returns the WS-Security header
fn sign_inner(xml: impl AsRef<str>, body_id: &str, config: SignConfig) -> Result<WsSecurity> {
    use quick_xml::se::to_string_with_root as xml_to_string;

    // Parse certificate to extract issuer and serial number
    let cert = CertificateEntry::from_der(&config.certificate)?;

    let timestamp_id = format!("TS-{}", uuid::Uuid::new_v4());

    // Canonicalize timestamp and body elements
    let timestamp = Timestamp::new(timestamp_id.clone(), config.timestamp_ttl)?;
    let modified_envelope = utils::add_body_id_to_envelope(xml.as_ref(), body_id)?;
    let timestamp_xml = xml_to_string("wsu:Timestamp", &timestamp)?;
    let body_xml = utils::extract_element(&modified_envelope, "Body")?;
    let timestamp_c14n = c14n::canonicalize(&timestamp_xml)?;
    let body_c14n = c14n::canonicalize(&body_xml)?;

    let timestamp_digest = HashAlg::Sha256.hash(timestamp_c14n.as_bytes())?;
    let body_digest = HashAlg::Sha256.hash(body_c14n.as_bytes())?;

    let timestamp_ref = Reference {
        uri: format!("#{timestamp_id}"),
        transforms: Some(Transforms {
            transform: vec![Transform {
                algorithm: algorithms::EXCLUSIVE_C14N.into(),
            }],
        }),
        digest_method: DigestMethod {
            algorithm: algorithms::SHA256.into(),
        },
        digest_value: BASE64.encode(&timestamp_digest),
    };

    let body_ref = Reference {
        uri: format!("#{body_id}"),
        transforms: Some(Transforms {
            transform: vec![Transform {
                algorithm: algorithms::EXCLUSIVE_C14N.into(),
            }],
        }),
        digest_method: DigestMethod {
            algorithm: algorithms::SHA256.into(),
        },
        digest_value: BASE64.encode(&body_digest),
    };

    let signed_info = SignedInfo {
        canon_method: CanonicalizationMethod {
            algorithm: algorithms::EXCLUSIVE_C14N.into(),
        },
        signature_method: SignatureMethod {
            algorithm: algorithms::RSA_SHA256.into(),
        },
        references: vec![timestamp_ref, body_ref],
    };

    // Serialize and canonicalize SignedInfo
    let signed_info_xml = xml_to_string("ds:SignedInfo", &signed_info)?;
    let signed_info_c14n = c14n::canonicalize(&signed_info_xml)?;

    // Sign the canonicalized SignedInfo
    let signature = rsa::sign(
        &config.private_key,
        signed_info_c14n.as_bytes(),
        HashAlg::Sha256,
    )?;

    let signature = Signature {
        signed_info,
        signature_value: BASE64.encode(signature.as_bytes()),
        key_info: KeyInfo {
            security_token_ref: SecurityTokenReference {
                x509_data: X509Data {
                    issuer_serial: X509IssuerSerial {
                        issuer_name: cert.issuer,
                        serial_number: cert.serial_number,
                    },
                },
            },
        },
    };
    Ok(WsSecurity {
        timestamp,
        signature,
    })
}
