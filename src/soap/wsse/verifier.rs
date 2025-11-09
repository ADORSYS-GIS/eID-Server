use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use quick_xml::de::from_str as xml_from_str;

use crate::crypto::{
    HashAlg,
    rsa::{self, RsaPublicKey, RsaSignature},
};
use crate::pki::truststore::TrustStore;
use crate::soap::wsse::timestamp::Timestamp;
use crate::soap::wsse::*;

/// Verify a signed SOAP envelope
pub async fn verify_envelope<T: TrustStore>(envelope_xml: &str, truststore: &T) -> Result<()> {
    // Extract and parse Security header
    let security_xml = utils::extract_element(envelope_xml, "Security")?;

    // Extract and validate Timestamp
    let timestamp = extract_timestamp(&security_xml)?;
    timestamp.validate()?;

    // Extract and parse signature
    let signature = extract_signature(&security_xml)?;

    // Verify reference digests
    verify_references(envelope_xml, &signature.signed_info.references)?;

    // Extract and canonicalize SignedInfo
    let signed_info_xml = utils::extract_element(&security_xml, "SignedInfo")?;
    let signed_info_c14n = c14n::canonicalize(&signed_info_xml, None)?;

    // Get certificate info
    let issuer_serial = &signature
        .key_info
        .security_token_ref
        .x509_data
        .issuer_serial;

    // Find certificate in truststore
    let cert_entry = truststore
        .get_cert_by_serial(&issuer_serial.serial_number)
        .await?
        .ok_or_else(|| Error::Invalid("Certificate not found in truststore".into()))?;

    if cert_entry.issuer != issuer_serial.issuer_name {
        return Err(Error::Invalid(format!(
            "Certificate issuer name mismatch: expected {}, got {}",
            cert_entry.issuer, issuer_serial.issuer_name
        )));
    }

    // Determine hash algorithm
    let hash_alg = match signature.signed_info.signature_method.algorithm.as_str() {
        algorithms::RSA_SHA256 => HashAlg::Sha256,
        alg => {
            return Err(Error::Invalid(format!(
                "Unsupported signature algorithm: {alg}",
            )));
        }
    };

    // Verify signature
    let cert = cert_entry.parse()?;
    let signature_bytes = BASE64.decode(&signature.signature_value)?;
    let public_key = RsaPublicKey::from_der(cert.tbs_certificate.subject_pki.raw)?;
    let rsa_sig = RsaSignature::new(public_key.key_size(), signature_bytes);

    if !rsa::verify(&public_key, signed_info_c14n.as_bytes(), &rsa_sig, hash_alg)? {
        return Err(Error::Invalid("Signature verification failed".into()));
    }
    Ok(())
}

/// Verify digest values for all references
fn verify_references(envelope_xml: &str, references: &[Reference]) -> Result<()> {
    for reference in references {
        let id = reference
            .uri
            .strip_prefix('#')
            .ok_or_else(|| Error::Invalid(format!("Invalid reference URI: {}", reference.uri)))?;

        let element_xml = utils::extract_element_by_id(envelope_xml, id)?;
        let transformed = apply_transforms(&element_xml, &reference.transforms)?;

        // Compute digest
        let hash_alg = match reference.digest_method.algorithm.as_str() {
            algorithms::SHA256 => HashAlg::Sha256,
            alg => {
                return Err(Error::Invalid(format!(
                    "Unsupported digest algorithm: {alg}",
                )));
            }
        };

        let computed_digest = hash_alg.hash(transformed.as_bytes())?;
        let expected_digest = BASE64.decode(&reference.digest_value)?;

        if computed_digest != expected_digest {
            return Err(Error::Invalid(format!(
                "Digest mismatch for reference: {}",
                reference.uri
            )));
        }
    }
    Ok(())
}

fn apply_transforms(data: &str, transforms: &Option<Transforms>) -> Result<String> {
    let mut result = data.to_string();

    if let Some(transforms) = transforms {
        for transform in &transforms.transform {
            result = match transform.algorithm.as_str() {
                algorithms::EXCLUSIVE_C14N => {
                    if let Some(ref inclusive_ns) = transform.inclusive_ns {
                        let prefixes: Vec<&str> =
                            inclusive_ns.prefix_list.split_whitespace().collect();
                        c14n::canonicalize(data, Some(&prefixes))?
                    } else {
                        c14n::canonicalize(data, None)?
                    }
                }
                alg => return Err(Error::Invalid(format!("Unsupported transform: {alg}"))),
            };
        }
    }
    Ok(result)
}

fn extract_timestamp(security_xml: &str) -> Result<Timestamp> {
    let timestamp_xml = utils::extract_element(security_xml, "Timestamp")?;
    xml_from_str(&timestamp_xml).map_err(Error::from)
}

fn extract_signature(security_xml: &str) -> Result<Signature> {
    let signature_xml = utils::extract_element(security_xml, "Signature")?;
    xml_from_str(&signature_xml).map_err(Error::from)
}
