//! Data structures and types for XML signature processing
//!
//! This module contains all the data structures, enums, and type definitions
//! used throughout the XML signature implementation.

use super::constants::*;
use serde::{Deserialize, Serialize};

/// Generic XML element with algorithm attribute - used for various signature components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmElement {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

// Type aliases for better readability
pub type CanonicalizationMethod = AlgorithmElement;
pub type SignatureMethod = AlgorithmElement;
pub type DigestMethod = AlgorithmElement;
pub type Transform = AlgorithmElement;

/// XML transforms container
#[derive(Debug, Clone, Serialize)]
pub struct Transforms {
    #[serde(rename = "Transform")]
    pub transform: Transform,
}

/// XML reference element
#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    #[serde(rename = "@URI")]
    pub uri: String,
    #[serde(rename = "Transforms")]
    pub transforms: Transforms,
    #[serde(rename = "DigestMethod")]
    pub digest_method: DigestMethod,
    #[serde(rename = "DigestValue")]
    pub digest_value: String,
}

/// XML SignedInfo element with optional namespace
#[derive(Debug, Serialize)]
pub struct SignedInfo {
    #[serde(rename = "@xmlns", skip_serializing_if = "Option::is_none")]
    pub xmlns: Option<String>,
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "Reference")]
    pub reference: Reference,
}

/// XML SignatureValue element
#[derive(Debug, Serialize)]
pub struct SignatureValue {
    #[serde(rename = "$text")]
    pub value: String,
}

/// XML X509Certificate element
#[derive(Debug, Serialize)]
pub struct X509Certificate {
    #[serde(rename = "$text")]
    pub certificate: String,
}

/// XML X509Data element
#[derive(Debug, Serialize)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    pub x509_certificate: X509Certificate,
}

/// XML KeyInfo element
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    #[serde(rename = "X509Data")]
    pub x509_data: X509Data,
}

/// Complete XML Signature element
#[derive(Debug, Serialize)]
pub struct Signature {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "KeyInfo")]
    pub key_info: KeyInfo,
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
    pub fn to_uri(&self) -> &'static str {
        RSA_SHA256_ALGORITHM
    }

    /// Get the digest algorithm URI
    /// All three WS-Security algorithm suites use the same digest algorithm: SHA256
    pub fn digest_uri(&self) -> &'static str {
        SHA256_DIGEST_ALGORITHM
    }

    /// Get the canonicalization algorithm URI
    /// All three WS-Security algorithm suites use the same canonicalization algorithm
    pub fn canonicalization_uri(&self) -> &'static str {
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
pub struct SignatureComponents {
    pub signature_value_b64: String,
    pub certificate_b64: String,
    pub signature_algorithm: String,
    pub canonicalization_algorithm: String,
    pub digest_algorithm: String,
    pub digest_value_b64: String,
}

/// Helper struct for parsing any XML element with text content
#[derive(Debug, Deserialize)]
pub struct XmlElementWithContent {
    #[serde(rename = "$text")]
    pub content: String,
}

/// Helper struct for parsing any XML element with a specific attribute
#[derive(Debug, Deserialize)]
pub struct XmlElementWithAttribute {
    #[serde(flatten)]
    pub attributes: std::collections::HashMap<String, String>,
}
