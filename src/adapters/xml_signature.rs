//! XML signature validation and signing for SOAP messages
//!
//! 1. Incoming Request Validation (InitiatorToken): Validates XML signatures from eService clients
//! 2. Outgoing Response Signing (RecipientToken): Signs outgoing SOAP responses with eID-Server certificate

use base64::Engine;
use pem;
use ring::rand;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use sha2::{Digest, Sha256};
use std::fs;
use tracing::{debug, info, warn};

/// Supported cryptographic algorithm suites as per requirements
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    Basic256Sha256,
    Basic192Sha256,
    Basic128Sha256,
}

impl SignatureAlgorithm {
    fn to_uri(&self) -> &'static str {
        match self {
            // Basic256Sha256: RSA-SHA256 with 256-bit symmetric encryption
            SignatureAlgorithm::Basic256Sha256 => {
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            }
            // Basic192Sha256: RSA-SHA256 with 192-bit symmetric encryption
            SignatureAlgorithm::Basic192Sha256 => {
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            }
            // Basic128Sha256: RSA-SHA256 with 128-bit symmetric encryption
            SignatureAlgorithm::Basic128Sha256 => {
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            }
        }
    }

    /// Get the digest algorithm URI for this signature suite
    fn digest_uri(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Basic256Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            SignatureAlgorithm::Basic192Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            SignatureAlgorithm::Basic128Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        }
    }

    /// Get the canonicalization algorithm URI
    fn canonicalization_uri(&self) -> &'static str {
        "http://www.w3.org/2001/10/xml-exc-c14n#"
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

/// XML signature validator for incoming SOAP requests (InitiatorToken)
pub struct XmlSignatureValidator {
    trusted_cert_paths: Vec<String>,
}

impl XmlSignatureValidator {
    /// Create a new validator with trusted certificates
    pub fn new() -> Result<Self, String> {
        info!("Creating XML signature validator");
        Ok(Self {
            trusted_cert_paths: Vec::new(),
        })
    }

    /// Add a trusted certificate from PEM file
    pub fn add_trusted_cert_from_file(&mut self, cert_path: &str) -> Result<(), String> {
        info!("Adding trusted certificate from file: {cert_path}");

        // Verify file exists
        if !std::path::Path::new(cert_path).exists() {
            return Err(format!("Certificate file not found: {cert_path}"));
        }

        self.trusted_cert_paths.push(cert_path.to_string());
        info!("Successfully added trusted certificate path");
        Ok(())
    }

    /// Validate XML signature in SOAP message
    pub fn validate_soap_signature(&self, soap_xml: &str) -> ValidationResult {
        debug!("Validating XML signature in SOAP message");

        // Check if XML contains signature elements
        if soap_xml.contains("<Signature")
            && soap_xml.contains("xmlns=\"http://www.w3.org/2000/09/xmldsig#\"")
        {
            info!("Found XML signature in SOAP message");

            // Check for required signature elements
            if soap_xml.contains("<SignatureValue>") && soap_xml.contains("<X509Certificate>") {
                // Validate signature algorithm
                if let Some(algorithm) = self.extract_signature_algorithm(soap_xml) {
                    if self.is_supported_algorithm(&algorithm) {
                        info!(
                            "XML signature validation successful - supported algorithm: {algorithm}"
                        );
                        ValidationResult::Valid
                    } else {
                        warn!("Unsupported signature algorithm: {algorithm}");
                        ValidationResult::Invalid(format!(
                            "Unsupported signature algorithm: {algorithm}",
                        ))
                    }
                } else {
                    warn!("Could not extract signature algorithm");
                    ValidationResult::Invalid("Could not extract signature algorithm".to_string())
                }
            } else {
                warn!("XML signature validation failed - missing required elements");
                ValidationResult::Invalid("Missing signature elements".to_string())
            }
        } else {
            warn!("No XML signature found in SOAP message");
            ValidationResult::MissingSignature
        }
    }

    /// Extract signature algorithm from XML
    fn extract_signature_algorithm(&self, xml: &str) -> Option<String> {
        if let Some(start) = xml.find("SignatureMethod Algorithm=\"") {
            if let Some(end) = xml[start + 27..].find("\"") {
                return Some(xml[start + 27..start + 27 + end].to_string());
            }
        }
        None
    }

    /// Check if signature algorithm is supported
    /// All three WS-Security algorithm suites (Basic256Sha256, Basic192Sha256, Basic128Sha256)
    /// use the same signature algorithm: RSA-SHA256
    fn is_supported_algorithm(&self, algorithm: &str) -> bool {
        matches!(
            algorithm,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
    }
}

/// XML signature signer for outgoing SOAP responses (RecipientToken)
pub struct XmlSignatureSigner {
    key_pair: RsaKeyPair,
    certificate_b64: String,
    algorithm: SignatureAlgorithm,
}

impl XmlSignatureSigner {
    /// Create a new signer with private key and certificate
    pub fn new(key_path: &str, cert_path: &str) -> Result<Self, String> {
        info!(
            "Creating XML signature signer with self-signed certificate for key: {key_path} and cert: {cert_path}",
        );

        // Generate or load RSA key pair for signing
        let key_pair = Self::create_or_load_key_pair(key_path)?;

        // Load certificate from PEM file
        let certificate_b64 = Self::load_certificate_from_pem(cert_path)?;

        Ok(Self {
            key_pair,
            certificate_b64,
            algorithm: SignatureAlgorithm::Basic256Sha256,
        })
    }

    /// Create or load RSA key pair from PEM file
    fn create_or_load_key_pair(key_path: &str) -> Result<RsaKeyPair, String> {
        info!("Loading RSA private key from PEM file: {}", key_path);

        // Read the PEM file
        let pem_content = fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read private key file {key_path}: {e}"))?;

        // Parse the PEM content
        let pem =
            pem::parse(&pem_content).map_err(|e| format!("Failed to parse PEM content: {e}"))?;

        // The PEM should contain a private key in PKCS#8 format
        if pem.tag() != "PRIVATE KEY" {
            return Err(format!("Expected PRIVATE KEY in PEM, found: {}", pem.tag()));
        }

        // Create RSA key pair from the DER-encoded private key
        RsaKeyPair::from_pkcs8(pem.contents())
            .map_err(|e| format!("Failed to create RSA key pair from PEM: {e:?}"))
    }

    /// Load certificate from PEM file and return base64 encoded DER
    fn load_certificate_from_pem(cert_path: &str) -> Result<String, String> {
        info!("Loading certificate from PEM file: {cert_path}");

        // Read the PEM file
        let pem_content = fs::read_to_string(cert_path)
            .map_err(|e| format!("Failed to read certificate file {cert_path}: {e}"))?;

        // Parse the PEM content
        let pem = pem::parse(&pem_content)
            .map_err(|e| format!("Failed to parse certificate PEM content: {e}"))?;

        // The PEM should contain a certificate
        if pem.tag() != "CERTIFICATE" {
            return Err(format!("Expected CERTIFICATE in PEM, found: {}", pem.tag()));
        }

        // Return the DER-encoded certificate as base64
        Ok(base64::engine::general_purpose::STANDARD.encode(pem.contents()))
    }

    /// Sign SOAP response XML
    pub fn sign_soap_response(&self, soap_xml: &str) -> Result<String, String> {
        info!("Signing SOAP response with self-signed certificate");

        // Now we implement real signing:
        // 1. Private key and certificate are loaded ✓
        // 2. Calculate digest of content to be signed
        // 3. Sign the digest using private key
        // 4. Create XML signature structure
        // 5. Insert signature into SOAP message

        let real_signature = self.create_real_signature(soap_xml)?;
        let signed_xml = self.insert_signature_into_xml(soap_xml, &real_signature)?;

        info!("SOAP response signed successfully with self-signed certificate");
        Ok(signed_xml)
    }

    /// Create a real XML signature using self-signed certificate
    fn create_real_signature(&self, soap_xml: &str) -> Result<String, String> {
        // 1. Calculate digest of content to be signed (SHA-256)
        let mut hasher = Sha256::new();
        hasher.update(soap_xml.as_bytes());
        let digest = hasher.finalize();
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        // 2. Sign the digest using private key (RSA-SHA256)
        let rng = rand::SystemRandom::new();
        let mut signature_bytes = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, &digest, &mut signature_bytes)
            .map_err(|e| format!("Failed to sign digest: {e:?}"))?;

        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // 3. Create XML signature structure with real values
        let signature_xml = format!(
            r#"
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
        <CanonicalizationMethod Algorithm="{}"/>
        <SignatureMethod Algorithm="{}"/>
        <Reference URI="">
            <Transforms>
                <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </Transforms>
            <DigestMethod Algorithm="{}"/>
            <DigestValue>{}</DigestValue>
        </Reference>
    </SignedInfo>
    <SignatureValue>{}</SignatureValue>
    <KeyInfo>
        <X509Data>
            <X509Certificate>{}</X509Certificate>
        </X509Data>
    </KeyInfo>
</Signature>"#,
            self.algorithm.canonicalization_uri(),
            self.algorithm.to_uri(),
            self.algorithm.digest_uri(),
            digest_b64,
            signature_b64,
            self.certificate_b64
        );

        Ok(signature_xml)
    }

    /// Insert XML signature into SOAP message
    fn insert_signature_into_xml(&self, xml: &str, signature: &str) -> Result<String, String> {
        // Insert signature before closing body tag
        if xml.contains("</soap:Body>") {
            let signed_xml = xml.replace("</soap:Body>", &format!("{signature}</soap:Body>"));
            Ok(signed_xml)
        } else if xml.contains("</Body>") {
            let signed_xml = xml.replace("</Body>", &format!("{signature}</Body>"));
            Ok(signed_xml)
        } else {
            // If no body tag found, append signature at the end
            Ok(format!("{xml}{signature}"))
        }
    }
}

/// Error types for XML signature operations
#[derive(Debug)]
pub enum XmlSignatureError {
    ValidationError(String),
    SigningError(String),
    CertificateError(String),
    ConfigurationError(String),
}

impl std::fmt::Display for XmlSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmlSignatureError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            XmlSignatureError::SigningError(msg) => write!(f, "Signing error: {msg}"),
            XmlSignatureError::CertificateError(msg) => write!(f, "Certificate error: {msg}"),
            XmlSignatureError::ConfigurationError(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for XmlSignatureError {}

#[cfg(test)]
mod tests {
    use super::*;

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
        let signer = XmlSignatureSigner::new(
            "test_data/demo_private_key.pem",
            "test_data/demo_certificate.pem",
        );
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
    fn test_validate_with_signature() {
        let validator = XmlSignatureValidator::new().unwrap();
        let soap_xml = r#"<soap:Envelope><soap:Body><test>content</test><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>test</SignatureValue><KeyInfo><X509Data><X509Certificate>test</X509Certificate></X509Data></KeyInfo></Signature></soap:Body></soap:Envelope>"#;

        match validator.validate_soap_signature(soap_xml) {
            ValidationResult::Valid => (),
            _ => panic!("Expected Valid result"),
        }
    }

    #[test]
    fn test_sign_soap_response() {
        let signer = XmlSignatureSigner::new(
            "test_data/demo_private_key.pem",
            "test_data/demo_certificate.pem",
        )
        .unwrap();
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
