//! XML signature signer for outgoing SOAP responses
//!
//! This module contains the XmlSignatureSigner implementation for signing
//! outgoing SOAP responses (RecipientToken).

use base64::Engine;
use quick_xml::se::to_string;
use ring::rand;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use sha2::{Digest, Sha256};
use std::fs;
use tracing::info;

use super::constants::*;
use super::types::*;
use super::utils::{canonicalize_xml, parse_and_validate_pem, remove_signatures_from_xml};

/// XML signature signer for outgoing SOAP responses (RecipientToken)
pub struct XmlSignatureSigner {
    key_pair: RsaKeyPair,
    certificate_b64: String,
    algorithm: SignatureAlgorithm,
}

impl XmlSignatureSigner {
    /// Reference structure for XML signatures
    fn create_reference(&self, digest_value: String) -> Reference {
        Reference {
            uri: "".to_string(),
            transforms: Transforms {
                transform: Transform {
                    algorithm: XMLDSIG_ENVELOPED_SIGNATURE.to_string(),
                },
            },
            digest_method: DigestMethod {
                algorithm: self.algorithm.digest_uri().to_string(),
            },
            digest_value,
        }
    }

    /// Create a new signer with private key and certificate from PEM data
    pub fn new(
        private_key_pem: impl Into<Vec<u8>>,
        cert_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, String> {
        let key_data = private_key_pem.into();
        let cert_data = cert_pem.into();

        info!(
            "Creating XML signature signer with certificate from PEM data ({} key bytes, {} cert bytes)",
            key_data.len(),
            cert_data.len()
        );

        let key_pair = Self::key_pair_from_pem_data(&key_data)?;
        let certificate_b64 = Self::load_certificate_from_pem_data(&cert_data)?;

        Ok(Self {
            key_pair,
            certificate_b64,
            algorithm: SignatureAlgorithm::Basic256Sha256,
        })
    }

    /// Create a new signer with private key and certificate from files (for backward compatibility)
    pub fn new_from_files(key_path: &str, cert_path: &str) -> Result<Self, String> {
        info!(
            "Creating XML signature signer with certificate from files: key={key_path}, cert={cert_path}",
        );

        let key_data = fs::read(key_path)
            .map_err(|e| format!("Failed to read private key file {key_path}: {e}"))?;
        let cert_data = fs::read(cert_path)
            .map_err(|e| format!("Failed to read certificate file {cert_path}: {e}"))?;

        Self::new(key_data, cert_data)
    }

    /// RSA key pair from PEM data
    fn key_pair_from_pem_data(pem_data: &[u8]) -> Result<RsaKeyPair, String> {
        info!(
            "Loading RSA private key from PEM data ({} bytes)",
            pem_data.len()
        );

        // Accept multiple private key formats utilizing comprehensive PEM tag constants
        let private_key_tags = &[
            PEM_PRIVATE_KEY_TAG,
            PEM_RSA_PRIVATE_KEY_TAG,
            PEM_EC_PRIVATE_KEY_TAG,
            PEM_DSA_PRIVATE_KEY_TAG,
            PEM_ENCRYPTED_PRIVATE_KEY_TAG,
        ];
        let pem = parse_and_validate_pem(pem_data, private_key_tags)?;

        RsaKeyPair::from_pkcs8(pem.contents())
            .map_err(|e| format!("Failed to create RSA key pair from PEM: {e:?}"))
    }

    /// Load certificate from PEM data and return base64 encoded DER
    fn load_certificate_from_pem_data(pem_data: &[u8]) -> Result<String, String> {
        info!(
            "Loading certificate from PEM data ({} bytes)",
            pem_data.len()
        );

        // Accept multiple certificate formats utilizing comprehensive PEM tag constants
        let certificate_tags = &[
            PEM_CERTIFICATE_TAG,
            PEM_X509_CERTIFICATE_TAG,
            PEM_TRUSTED_CERTIFICATE_TAG,
        ];
        let pem = parse_and_validate_pem(pem_data, certificate_tags)?;

        Ok(base64::engine::general_purpose::STANDARD.encode(pem.contents()))
    }

    /// Sign SOAP response XML
    pub fn sign_soap_response(&self, soap_xml: &str) -> Result<String, String> {
        info!("Signing SOAP response with self-signed certificate");

        let real_signature = self.create_real_signature(soap_xml)?;
        let signed_xml = self.insert_signature_into_xml(soap_xml, &real_signature)?;

        info!("SOAP response signed successfully with self-signed certificate");
        Ok(signed_xml)
    }

    /// XMLDSig signature following W3C standards
    fn create_real_signature(&self, soap_xml: &str) -> Result<String, String> {
        info!("Creating XMLDSig compliant signature");

        // Step 1: Calculate digest of the referenced content (the SOAP document)
        // Apply enveloped-signature transform (remove any existing signatures)
        let content_to_digest = remove_signatures_from_xml(soap_xml)?;
        let content_digest = self.calculate_content_digest(&content_to_digest)?;
        let content_digest_b64 = base64::engine::general_purpose::STANDARD.encode(content_digest);

        // Step 2: Reference structure
        let reference = self.create_reference(content_digest_b64);

        // Step 3: SignedInfo element using serde structs
        let signed_info = SignedInfo {
            xmlns: Some(XMLDSIG_NAMESPACE.to_string()),
            canonicalization_method: CanonicalizationMethod {
                algorithm: self.algorithm.canonicalization_uri().to_string(),
            },
            signature_method: SignatureMethod {
                algorithm: self.algorithm.to_uri().to_string(),
            },
            reference: reference.clone(),
        };

        let signed_info_xml =
            to_string(&signed_info).map_err(|e| format!("Failed to serialize SignedInfo: {e}"))?;

        // Step 4: Canonicalize the SignedInfo element (C14N)
        let canonicalized_signed_info = canonicalize_xml(&signed_info_xml)?;

        // Step 5: Sign the canonicalized SignedInfo (not the entire document!)
        let signed_info_digest = self.calculate_content_digest(&canonicalized_signed_info)?;
        let signature_bytes = self.sign_digest(&signed_info_digest)?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // Step 6: complete signature structure using serde structs
        let signature = Signature {
            xmlns: XMLDSIG_NAMESPACE.to_string(),
            signed_info: SignedInfo {
                xmlns: None, // No xmlns needed since parent Signature element has it
                canonicalization_method: CanonicalizationMethod {
                    algorithm: self.algorithm.canonicalization_uri().to_string(),
                },
                signature_method: SignatureMethod {
                    algorithm: self.algorithm.to_uri().to_string(),
                },
                reference,
            },
            signature_value: SignatureValue {
                value: signature_b64,
            },
            key_info: KeyInfo {
                x509_data: X509Data {
                    x509_certificate: X509Certificate {
                        certificate: self.certificate_b64.clone(),
                    },
                },
            },
        };

        let signature_xml =
            to_string(&signature).map_err(|e| format!("Failed to serialize Signature: {e}"))?;

        info!("XMLDSig compliant signature created successfully");
        Ok(signature_xml)
    }

    /// Calculate SHA-256 digest of content
    fn calculate_content_digest(&self, content: &str) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    /// Sign digest using RSA-SHA256
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let rng = rand::SystemRandom::new();
        let mut signature_bytes = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, digest, &mut signature_bytes)
            .map_err(|e| format!("Failed to sign digest: {e:?}"))?;
        Ok(signature_bytes)
    }

    /// Insert XML signature into SOAP message
    fn insert_signature_into_xml(&self, xml: &str, signature: &str) -> Result<String, String> {
        if xml.contains(SOAP_BODY_END_TAG) {
            let signed_xml = xml.replace(SOAP_BODY_END_TAG, &format!("{signature}</soap:Body>"));
            Ok(signed_xml)
        } else if xml.contains(BODY_END_TAG) {
            let signed_xml = xml.replace(BODY_END_TAG, &format!("{signature}</Body>"));
            Ok(signed_xml)
        } else {
            // If no body tag found, append signature at the end
            Ok(format!("{xml}{signature}"))
        }
    }
}
