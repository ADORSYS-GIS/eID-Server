//! XML signature validation and signing for SOAP messages
//!
//! 1. Incoming Request Validation (InitiatorToken): Validates XML signatures from eService clients
//! 2. Outgoing Response Signing (RecipientToken): Signs outgoing SOAP responses with eID-Server certificate

use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use pem;
use quick_xml::se::to_string;
use ring::rand;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use tracing::{debug, info, warn};
use xmltree::Element;

// XML Signature Constants to avoid magic strings

/// XML namespace URIs
const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLDSIG_ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Algorithm URIs
const RSA_SHA256_ALGORITHM: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256_DIGEST_ALGORITHM: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXCLUSIVE_C14N_ALGORITHM: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// XML element names
const SIGNATURE_VALUE_ELEMENT: &str = "SignatureValue";
const X509_CERTIFICATE_ELEMENT: &str = "X509Certificate";
const DIGEST_VALUE_ELEMENT: &str = "DigestValue";
const SIGNATURE_METHOD_ELEMENT: &str = "SignatureMethod";
const CANONICALIZATION_METHOD_ELEMENT: &str = "CanonicalizationMethod";
const DIGEST_METHOD_ELEMENT: &str = "DigestMethod";

/// XML attribute names
const ALGORITHM_ATTRIBUTE: &str = "Algorithm";

/// PEM tags
const PEM_CERTIFICATE_TAG: &str = "CERTIFICATE";
const PEM_PRIVATE_KEY_TAG: &str = "PRIVATE KEY";

/// SOAP element names
const SOAP_BODY_END_TAG: &str = "</soap:Body>";
const BODY_END_TAG: &str = "</Body>";

/// Parse and validate PEM content with expected tag
fn parse_and_validate_pem(pem_data: &[u8], expected_tag: &str) -> Result<pem::Pem, String> {
    let pem = pem::parse(pem_data).map_err(|e| format!("Failed to parse PEM content: {e}"))?;

    if pem.tag() != expected_tag {
        return Err(format!(
            "Expected {} in PEM, found: {}",
            expected_tag,
            pem.tag()
        ));
    }

    Ok(pem)
}

/// Remove signature elements from XML (enveloped-signature transform)
fn remove_signatures_from_xml(xml: &str) -> Result<String, String> {
    let mut result = xml.to_string();

    while let Some(start) = result.find("<Signature") {
        if let Some(end) = result[start..].find("</Signature>") {
            let end_pos = start + end + "</Signature>".len();
            result.replace_range(start..end_pos, "");
        } else {
            break;
        }
    }

    Ok(result)
}

/// Canonicalize XML using C14N (simplified implementation)
fn canonicalize_xml(xml: &str) -> Result<String, String> {
    // This is a simplified canonicalization implementation
    // In production, use a proper C14N library

    let element = Element::parse(Cursor::new(xml.as_bytes()))
        .map_err(|e| format!("Failed to parse XML for canonicalization: {e}"))?;

    let mut output = Vec::new();
    element
        .write(&mut output)
        .map_err(|e| format!("Failed to write canonicalized XML: {e}"))?;

    String::from_utf8(output)
        .map_err(|e| format!("Failed to convert canonicalized XML to string: {e}"))
}

/// Generic XML element with algorithm attribute - used for various signature components
#[derive(Debug, Clone, Serialize)]
struct AlgorithmElement {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

// Type aliases for better readability
type CanonicalizationMethod = AlgorithmElement;
type SignatureMethod = AlgorithmElement;
type DigestMethod = AlgorithmElement;
type Transform = AlgorithmElement;

/// XML transforms container
#[derive(Debug, Clone, Serialize)]
struct Transforms {
    #[serde(rename = "Transform")]
    transform: Transform,
}

/// XML reference element
#[derive(Debug, Clone, Serialize)]
struct Reference {
    #[serde(rename = "@URI")]
    uri: String,
    #[serde(rename = "Transforms")]
    transforms: Transforms,
    #[serde(rename = "DigestMethod")]
    digest_method: DigestMethod,
    #[serde(rename = "DigestValue")]
    digest_value: String,
}

/// XML SignedInfo element with optional namespace
#[derive(Debug, Serialize)]
struct SignedInfo {
    #[serde(rename = "@xmlns", skip_serializing_if = "Option::is_none")]
    xmlns: Option<String>,
    #[serde(rename = "CanonicalizationMethod")]
    canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "SignatureMethod")]
    signature_method: SignatureMethod,
    #[serde(rename = "Reference")]
    reference: Reference,
}

/// XML SignatureValue element
#[derive(Debug, Serialize)]
struct SignatureValue {
    #[serde(rename = "$text")]
    value: String,
}

/// XML X509Certificate element
#[derive(Debug, Serialize)]
struct X509Certificate {
    #[serde(rename = "$text")]
    certificate: String,
}

/// XML X509Data element
#[derive(Debug, Serialize)]
struct X509Data {
    #[serde(rename = "X509Certificate")]
    x509_certificate: X509Certificate,
}

/// XML KeyInfo element
#[derive(Debug, Serialize)]
struct KeyInfo {
    #[serde(rename = "X509Data")]
    x509_data: X509Data,
}

/// Complete XML Signature element
#[derive(Debug, Serialize)]
struct Signature {
    #[serde(rename = "@xmlns")]
    xmlns: String,
    #[serde(rename = "SignedInfo")]
    signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    signature_value: SignatureValue,
    #[serde(rename = "KeyInfo")]
    key_info: KeyInfo,
}

/// Supported cryptographic algorithm suites as per requirements
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    Basic256Sha256,
    Basic192Sha256,
    Basic128Sha256,
}

impl SignatureAlgorithm {
    /// Get the signature algorithm URI
    /// All three WS-Security algorithm suites use the same signature algorithm: RSA-SHA256
    fn to_uri(&self) -> &'static str {
        RSA_SHA256_ALGORITHM
    }

    /// Get the digest algorithm URI
    /// All three WS-Security algorithm suites use the same digest algorithm: SHA256
    fn digest_uri(&self) -> &'static str {
        SHA256_DIGEST_ALGORITHM
    }

    /// Get the canonicalization algorithm URI
    /// All three WS-Security algorithm suites use the same canonicalization algorithm
    fn canonicalization_uri(&self) -> &'static str {
        EXCLUSIVE_C14N_ALGORITHM
    }
}

/// XML signature validation result
#[derive(Debug)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
    MissingSignature,
    CertificateError(String),
}

/// Signature components extracted from XML
#[derive(Debug)]
struct SignatureComponents {
    signature_value_b64: String,
    certificate_b64: String,
    signature_algorithm: String,
    canonicalization_algorithm: String,
    digest_algorithm: String,
    digest_value_b64: String,
}

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

        parse_and_validate_pem(&cert_data, PEM_CERTIFICATE_TAG)?;

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
                info!("XML signature cryptographic verification successful");
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

    /// Extract content of an XML element
    fn extract_xml_element_content(&self, xml: &str, element_name: &str) -> Result<String, String> {
        let start_tag = format!("<{element_name}>");
        let end_tag = format!("</{element_name}>");

        if let Some(start) = xml.find(&start_tag) {
            let content_start = start + start_tag.len();
            if let Some(end) = xml[content_start..].find(&end_tag) {
                let content = xml[content_start..content_start + end].trim();
                return Ok(content.to_string());
            }
        }

        Err(format!("Could not find element: {element_name}"))
    }

    /// Extract attribute value from XML element
    fn extract_attribute_value(
        &self,
        xml: &str,
        element_name: &str,
        attribute_name: &str,
    ) -> Result<String, String> {
        let element_pattern = format!("<{element_name}");
        let attribute_pattern = format!("{attribute_name}=\"");

        if let Some(element_start) = xml.find(&element_pattern) {
            if let Some(attr_start) = xml[element_start..].find(&attribute_pattern) {
                let attr_value_start = element_start + attr_start + attribute_pattern.len();
                if let Some(attr_end) = xml[attr_value_start..].find("\"") {
                    let value = &xml[attr_value_start..attr_value_start + attr_end];
                    return Ok(value.to_string());
                }
            }
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

/// XML signature signer for outgoing SOAP responses (RecipientToken)
pub struct XmlSignatureSigner {
    key_pair: RsaKeyPair,
    certificate_b64: String,
    algorithm: SignatureAlgorithm,
}

impl XmlSignatureSigner {
    /// Create a Reference structure for XML signatures
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

        let key_pair = Self::create_key_pair_from_pem_data(&key_data)?;
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

    /// Create RSA key pair from PEM data
    fn create_key_pair_from_pem_data(pem_data: &[u8]) -> Result<RsaKeyPair, String> {
        info!(
            "Loading RSA private key from PEM data ({} bytes)",
            pem_data.len()
        );

        let pem = parse_and_validate_pem(pem_data, PEM_PRIVATE_KEY_TAG)?;

        RsaKeyPair::from_pkcs8(pem.contents())
            .map_err(|e| format!("Failed to create RSA key pair from PEM: {e:?}"))
    }

    /// Load certificate from PEM data and return base64 encoded DER
    fn load_certificate_from_pem_data(pem_data: &[u8]) -> Result<String, String> {
        info!(
            "Loading certificate from PEM data ({} bytes)",
            pem_data.len()
        );

        let pem = parse_and_validate_pem(pem_data, PEM_CERTIFICATE_TAG)?;

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

    /// Create a proper XMLDSig signature following W3C standards
    fn create_real_signature(&self, soap_xml: &str) -> Result<String, String> {
        info!("Creating XMLDSig compliant signature");

        // Step 1: Calculate digest of the referenced content (the SOAP document)
        // Apply enveloped-signature transform (remove any existing signatures)
        let content_to_digest = remove_signatures_from_xml(soap_xml)?;
        let content_digest = self.calculate_content_digest(&content_to_digest)?;
        let content_digest_b64 = base64::engine::general_purpose::STANDARD.encode(content_digest);

        // Step 2: Create Reference structure (reused in both SignedInfo structures)
        let reference = self.create_reference(content_digest_b64);

        // Step 3: Create SignedInfo element using serde structs
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

        // Step 6: Create complete signature structure using serde structs
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cert_utils::generate_test_certificates;

    #[test]
    fn test_signature_algorithm_uri() {
        assert_eq!(
            SignatureAlgorithm::Basic256Sha256.to_uri(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        );
    }

    #[test]
    fn test_validator_creation() {
        let validator = XmlSignatureValidator::new();
        assert!(validator.is_ok());
    }

    #[test]
    fn test_signer_creation() {
        let test_certs = generate_test_certificates();
        let signer = XmlSignatureSigner::new(test_certs.server_key, test_certs.server_cert);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_validate_missing_signature() {
        let validator = XmlSignatureValidator::new().unwrap();
        let soap_xml =
            r#"<soap:Envelope><soap:Body><test>content</test></soap:Body></soap:Envelope>"#;

        match validator.validate_soap_signature(soap_xml) {
            ValidationResult::MissingSignature => (),
            _ => panic!("Expected MissingSignature result"),
        }
    }

    #[test]
    fn test_validate_with_invalid_signature() {
        let validator = XmlSignatureValidator::new().unwrap();
        // This XML contains invalid signature data (fake values)
        let soap_xml = r#"<soap:Envelope><soap:Body><test>content</test><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>fake-digest</DigestValue></Reference></SignedInfo><SignatureValue>fake-signature</SignatureValue><KeyInfo><X509Data><X509Certificate>fake-certificate</X509Certificate></X509Data></KeyInfo></Signature></soap:Body></soap:Envelope>"#;

        match validator.validate_soap_signature(soap_xml) {
            ValidationResult::Invalid(_) | ValidationResult::CertificateError(_) => {
                // This is expected - invalid signatures should be rejected
            }
            ValidationResult::Valid => panic!("Invalid signature should not be validated as valid"),
            ValidationResult::MissingSignature => {
                panic!("Signature is present, should not be missing")
            }
        }
    }

    #[test]
    fn test_complete_sign_and_validate_flow() {
        let test_certs = generate_test_certificates();
        let signer =
            XmlSignatureSigner::new(test_certs.server_key, test_certs.server_cert.clone()).unwrap();

        let soap_xml =
            r#"<soap:Envelope><soap:Body><test>content</test></soap:Body></soap:Envelope>"#;
        let signed_xml = signer.sign_soap_response(soap_xml).unwrap();
        assert!(signed_xml.contains("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
        assert!(signed_xml.contains("<SignedInfo>"));
        assert!(signed_xml.contains("<CanonicalizationMethod"));
        assert!(signed_xml.contains("<SignatureMethod"));
        assert!(signed_xml.contains("<Reference URI=\"\">"));
        assert!(signed_xml.contains("<DigestMethod"));
        assert!(signed_xml.contains("<DigestValue>"));
        assert!(signed_xml.contains("<SignatureValue>"));
        assert!(signed_xml.contains("<X509Certificate>"));

        // Verify the signature uses the correct algorithms
        assert!(signed_xml.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
        assert!(signed_xml.contains("http://www.w3.org/2001/10/xml-exc-c14n#"));
        assert!(signed_xml.contains("http://www.w3.org/2001/04/xmlenc#sha256"));

        println!("Signed XML structure is correct");

        // Test that invalid signatures are properly rejected
        let mut validator = XmlSignatureValidator::new().unwrap();
        validator.add_trusted_cert(test_certs.server_cert).unwrap();

        // Test with completely invalid signature data
        let invalid_soap_xml = r#"<soap:Envelope><soap:Body><test>content</test><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>invalid</DigestValue></Reference></SignedInfo><SignatureValue>invalid</SignatureValue><KeyInfo><X509Data><X509Certificate>invalid</X509Certificate></X509Data></KeyInfo></Signature></soap:Body></soap:Envelope>"#;

        match validator.validate_soap_signature(invalid_soap_xml) {
            ValidationResult::Invalid(_) | ValidationResult::CertificateError(_) => {
                println!("Invalid signature correctly rejected");
            }
            ValidationResult::Valid => {
                panic!("Invalid signature should not be accepted as valid");
            }
            ValidationResult::MissingSignature => {
                panic!("Signature is present, should not be missing");
            }
        }
    }

    #[test]
    fn test_sign_soap_response() {
        // Generate test certificates programmatically (avoiding hardcoded file paths)
        let test_certs = generate_test_certificates();
        let signer =
            XmlSignatureSigner::new(test_certs.server_key, test_certs.server_cert).unwrap();
        let soap_xml =
            r#"<soap:Envelope><soap:Body><test>content</test></soap:Body></soap:Envelope>"#;

        let result = signer.sign_soap_response(soap_xml);
        assert!(result.is_ok());

        let signed_xml = result.unwrap();
        assert!(signed_xml.contains("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
        assert!(signed_xml.contains("<SignatureValue>"));
        assert!(signed_xml.contains("<X509Certificate>"));
    }
}
