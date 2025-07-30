//! XML signature validator for incoming SOAP requests
//!
//! This module contains the XmlSignatureValidator implementation for validating
//! XML signatures in incoming SOAP messages (InitiatorToken).

use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use quick_xml::{Reader, events::Event, se::to_string};
use sha2::{Digest, Sha256};
use std::fs;
use tracing::{debug, info, warn};

use super::constants::*;
use super::types::*;
use super::utils::{canonicalize_xml, parse_and_validate_pem, remove_signatures_from_xml};

/// XML signature validator for incoming SOAP requests (InitiatorToken)
pub struct XmlSignatureValidator {
    trusted_certs: Vec<Vec<u8>>,
}

impl XmlSignatureValidator {
    /// Create a new validator with trusted certificates
    pub fn new() -> Result<Self, String> {
        info!("Creating XML signature validator");
        Ok(Self {
            trusted_certs: Vec::new(),
        })
    }

    /// Add a trusted certificate from PEM data
    pub fn add_trusted_cert(&mut self, cert_pem: impl Into<Vec<u8>>) -> Result<(), String> {
        let cert_data = cert_pem.into();
        info!(
            "Adding trusted certificate from PEM data ({} bytes)",
            cert_data.len()
        );

        // Accept multiple certificate formats utilizing comprehensive PEM tag constants
        let certificate_tags = &[
            PEM_CERTIFICATE_TAG,
            PEM_X509_CERTIFICATE_TAG,
            PEM_TRUSTED_CERTIFICATE_TAG,
        ];
        parse_and_validate_pem(&cert_data, certificate_tags)?;

        self.trusted_certs.push(cert_data);
        info!("Successfully added trusted certificate");
        Ok(())
    }

    /// Add a trusted certificate from PEM file (for backward compatibility)
    pub fn add_trusted_cert_from_file(&mut self, cert_path: &str) -> Result<(), String> {
        info!("Adding trusted certificate from file: {cert_path}");

        let cert_data = fs::read(cert_path)
            .map_err(|e| format!("Failed to read certificate file {cert_path}: {e}"))?;

        self.add_trusted_cert(cert_data)
    }

    /// Validate XML signature in SOAP message with proper cryptographic verification
    pub fn validate_soap_signature(&self, soap_xml: &str) -> ValidationResult {
        debug!("Validating XML signature in SOAP message with cryptographic verification");

        if !soap_xml.contains("<Signature")
            || !soap_xml.contains(&format!("xmlns=\"{XMLDSIG_NAMESPACE}\""))
        {
            warn!("No XML signature found in SOAP message");
            return ValidationResult::MissingSignature;
        }

        info!("Found XML signature in SOAP message, performing cryptographic verification");

        let signature_components = match self.extract_signature_components(soap_xml) {
            Ok(components) => components,
            Err(e) => {
                warn!("Failed to extract signature components: {e}");
                return ValidationResult::Invalid(format!(
                    "Failed to extract signature components: {e}"
                ));
            }
        };

        if !self.is_supported_algorithm(&signature_components.signature_algorithm) {
            warn!(
                "Unsupported signature algorithm: {}",
                signature_components.signature_algorithm
            );
            return ValidationResult::Invalid(format!(
                "Unsupported signature algorithm: {}",
                signature_components.signature_algorithm
            ));
        }

        let certificate =
            match self.parse_and_validate_certificate(&signature_components.certificate_b64) {
                Ok(cert) => cert,
                Err(e) => {
                    warn!("Certificate validation failed: {e}");
                    return ValidationResult::CertificateError(e);
                }
            };
        match self.verify_signature_cryptographically(soap_xml, &signature_components, &certificate)
        {
            Ok(true) => {
                info!(
                    "XML signature cryptographic verification successful - algorithm: {}, digest: {}, cert_subject: {:?}",
                    signature_components.signature_algorithm,
                    signature_components.digest_algorithm,
                    certificate.subject_name()
                );
                ValidationResult::Valid
            }
            Ok(false) => {
                warn!("XML signature cryptographic verification failed");
                ValidationResult::Invalid("Cryptographic signature verification failed".to_string())
            }
            Err(e) => {
                warn!("Error during signature verification: {e}");
                ValidationResult::Invalid(format!("Signature verification error: {e}"))
            }
        }
    }

    /// Check if signature algorithm is supported
    /// All three WS-Security algorithm suites (Basic256Sha256, Basic192Sha256, Basic128Sha256)
    /// use the same signature algorithm: RSA-SHA256
    fn is_supported_algorithm(&self, algorithm: &str) -> bool {
        algorithm == RSA_SHA256_ALGORITHM
    }

    /// Extract all signature components from XML
    fn extract_signature_components(&self, xml: &str) -> Result<SignatureComponents, String> {
        debug!("Extracting signature components from XML");

        let signature_value_b64 = self.extract_xml_element_content(xml, SIGNATURE_VALUE_ELEMENT)?;
        let certificate_b64 = self.extract_xml_element_content(xml, X509_CERTIFICATE_ELEMENT)?;
        let signature_algorithm =
            self.extract_attribute_value(xml, SIGNATURE_METHOD_ELEMENT, ALGORITHM_ATTRIBUTE)?;
        let canonicalization_algorithm = self.extract_attribute_value(
            xml,
            CANONICALIZATION_METHOD_ELEMENT,
            ALGORITHM_ATTRIBUTE,
        )?;
        let digest_algorithm =
            self.extract_attribute_value(xml, DIGEST_METHOD_ELEMENT, ALGORITHM_ATTRIBUTE)?;
        let digest_value_b64 = self.extract_xml_element_content(xml, DIGEST_VALUE_ELEMENT)?;

        Ok(SignatureComponents {
            signature_value_b64,
            certificate_b64,
            signature_algorithm,
            canonicalization_algorithm,
            digest_algorithm,
            digest_value_b64,
        })
    }

    /// Extract content of an XML element using proper XML parsing
    fn extract_xml_element_content(&self, xml: &str, element_name: &str) -> Result<String, String> {
        debug!("Extracting content for element: {}", element_name);

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut in_target_element = false;
        let mut content = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == element_name.as_bytes() {
                        in_target_element = true;
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_target_element {
                        content = e
                            .unescape()
                            .map_err(|e| format!("Failed to unescape text: {e}"))?
                            .to_string();
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == element_name.as_bytes() && in_target_element {
                        return Ok(content.trim().to_string());
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parsing error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Err(format!("Could not find element: {element_name}"))
    }

    /// Extract attribute value from XML element using proper XML parsing
    fn extract_attribute_value(
        &self,
        xml: &str,
        element_name: &str,
        attribute_name: &str,
    ) -> Result<String, String> {
        debug!(
            "Extracting attribute '{}' from element '{}'",
            attribute_name, element_name
        );

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    if e.name().as_ref() == element_name.as_bytes() {
                        for attr in e.attributes() {
                            let attr =
                                attr.map_err(|e| format!("Failed to parse attribute: {e}"))?;
                            if attr.key.as_ref() == attribute_name.as_bytes() {
                                return attr
                                    .unescape_value()
                                    .map_err(|e| format!("Failed to unescape attribute value: {e}"))
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parsing error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Err(format!(
            "Could not find attribute {attribute_name} in element {element_name}"
        ))
    }

    /// Parse and validate X.509 certificate
    fn parse_and_validate_certificate(&self, cert_b64: &str) -> Result<X509, String> {
        debug!("Parsing and validating X.509 certificate");

        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .map_err(|e| format!("Failed to decode base64 certificate: {e}"))?;

        let certificate = X509::from_der(&cert_der)
            .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;

        let now = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| format!("Failed to get current time: {e}"))?;

        if certificate.not_before() > now {
            return Err("Certificate is not yet valid".to_string());
        }

        if certificate.not_after() < now {
            return Err("Certificate has expired".to_string());
        }

        if !self.trusted_certs.is_empty() {
            let cert_pem = certificate
                .to_pem()
                .map_err(|e| format!("Failed to convert certificate to PEM: {e}"))?;

            let is_trusted = self.trusted_certs.iter().any(|trusted_cert| {
                // Compare certificates (simplified comparison)
                trusted_cert == &cert_pem
            });

            if !is_trusted {
                return Err("Certificate is not in trusted store".to_string());
            }
        }

        info!("Certificate validation successful");
        Ok(certificate)
    }

    /// Verify signature cryptographically
    fn verify_signature_cryptographically(
        &self,
        soap_xml: &str,
        components: &SignatureComponents,
        certificate: &X509,
    ) -> Result<bool, String> {
        debug!("Performing cryptographic signature verification");

        let public_key = certificate
            .public_key()
            .map_err(|e| format!("Failed to extract public key from certificate: {e}"))?;

        // Create SignedInfo using serde structs
        let signed_info = SignedInfo {
            xmlns: Some(XMLDSIG_NAMESPACE.to_string()),
            canonicalization_method: CanonicalizationMethod {
                algorithm: components.canonicalization_algorithm.clone(),
            },
            signature_method: SignatureMethod {
                algorithm: components.signature_algorithm.clone(),
            },
            reference: Reference {
                uri: "".to_string(),
                transforms: Transforms {
                    transform: Transform {
                        algorithm: XMLDSIG_ENVELOPED_SIGNATURE.to_string(),
                    },
                },
                digest_method: DigestMethod {
                    algorithm: components.digest_algorithm.clone(),
                },
                digest_value: components.digest_value_b64.clone(),
            },
        };

        let signed_info_xml =
            to_string(&signed_info).map_err(|e| format!("Failed to serialize SignedInfo: {e}"))?;

        // Canonicalize SignedInfo (simplified)
        let canonicalized_signed_info = canonicalize_xml(&signed_info_xml)?;

        if !self.verify_digest_value(soap_xml, &components.digest_value_b64)? {
            warn!("Digest value verification failed");
            return Ok(false);
        }

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&components.signature_value_b64)
            .map_err(|e| format!("Failed to decode signature: {e}"))?;

        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
            .map_err(|e| format!("Failed to create verifier: {e}"))?;

        verifier
            .update(canonicalized_signed_info.as_bytes())
            .map_err(|e| format!("Failed to update verifier: {e}"))?;

        let is_valid = verifier
            .verify(&signature_bytes)
            .map_err(|e| format!("Failed to verify signature: {e}"))?;

        if is_valid {
            info!("Cryptographic signature verification successful");
        } else {
            warn!("Cryptographic signature verification failed");
        }

        Ok(is_valid)
    }

    /// Verify digest value against content
    fn verify_digest_value(
        &self,
        soap_xml: &str,
        expected_digest_b64: &str,
    ) -> Result<bool, String> {
        // Apply enveloped-signature transform (remove signatures)
        let content_without_signatures = remove_signatures_from_xml(soap_xml)?;

        let mut hasher = Sha256::new();
        hasher.update(content_without_signatures.as_bytes());
        let calculated_digest = hasher.finalize();
        let calculated_digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(calculated_digest);

        Ok(calculated_digest_b64 == expected_digest_b64)
    }
}
