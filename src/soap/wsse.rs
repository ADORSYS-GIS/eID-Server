mod c14n;
mod error;
mod signer;
#[cfg(test)]
mod tests;
mod timestamp;
mod utils;
mod verifier;

pub use error::Error;
pub use signer::{SignConfig, sign_envelope};
pub use verifier::verify_envelope;

use crate::soap::wsse::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

// Algorithm URIs as per WS-Security Policy Basic256Sha256
pub mod algorithms {
    // Digest algorithms
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    // Signature algorithms
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    // Canonicalization algorithms
    pub const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

    // Transform algorithms
    pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
}

// Namespaces
pub mod ns {
    pub const WSSE: &str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    pub const WSU: &str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSecurity {
    #[serde(rename(serialize = "wsu:Timestamp", deserialize = "Timestamp"))]
    pub timestamp: Timestamp,
    #[serde(rename(serialize = "ds:Signature", deserialize = "Signature"))]
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename(serialize = "ds:SignedInfo", deserialize = "SignedInfo"))]
    pub signed_info: SignedInfo,

    #[serde(rename(serialize = "ds:SignatureValue", deserialize = "SignatureValue"))]
    pub signature_value: String,

    #[serde(rename(serialize = "ds:KeyInfo", deserialize = "KeyInfo"))]
    pub key_info: KeyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInfo {
    #[serde(rename(
        serialize = "ds:CanonicalizationMethod",
        deserialize = "CanonicalizationMethod"
    ))]
    pub canon_method: CanonicalizationMethod,

    #[serde(rename(serialize = "ds:SignatureMethod", deserialize = "SignatureMethod"))]
    pub signature_method: SignatureMethod,

    #[serde(rename(serialize = "ds:Reference", deserialize = "Reference"), default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalizationMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "@URI")]
    pub uri: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(serialize = "ds:Transforms", deserialize = "Transforms"))]
    pub transforms: Option<Transforms>,

    #[serde(rename(serialize = "ds:DigestMethod", deserialize = "DigestMethod"))]
    pub digest_method: DigestMethod,

    #[serde(rename(serialize = "ds:DigestValue", deserialize = "DigestValue"))]
    pub digest_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transforms {
    #[serde(rename(serialize = "ds:Transform", deserialize = "Transform"), default)]
    pub transform: Vec<Transform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transform {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename(serialize = "wsse:SecurityTokenReference"))]
    #[serde(rename(deserialize = "SecurityTokenReference"))]
    pub security_token_ref: SecurityTokenReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTokenReference {
    #[serde(rename(serialize = "ds:X509Data", deserialize = "X509Data"))]
    pub x509_data: X509Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509Data {
    #[serde(rename(serialize = "ds:X509IssuerSerial", deserialize = "X509IssuerSerial"))]
    pub issuer_serial: X509IssuerSerial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509IssuerSerial {
    #[serde(rename(serialize = "ds:X509IssuerName", deserialize = "X509IssuerName"))]
    pub issuer_name: String,

    #[serde(rename(serialize = "ds:X509SerialNumber", deserialize = "X509SerialNumber"))]
    pub serial_number: String,
}
