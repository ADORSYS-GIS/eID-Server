//! XML signature constants and algorithm URIs
//!
//! This module contains all the constants used throughout the XML signature implementation
//! to avoid magic strings and provide a centralized location for configuration.

/// XML namespace URIs
pub const XMLDSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XMLDSIG_ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Algorithm URIs
pub const RSA_SHA256_ALGORITHM: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const SHA256_DIGEST_ALGORITHM: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const EXCLUSIVE_C14N_ALGORITHM: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// XML element names
pub const SIGNATURE_VALUE_ELEMENT: &str = "SignatureValue";
pub const X509_CERTIFICATE_ELEMENT: &str = "X509Certificate";
pub const DIGEST_VALUE_ELEMENT: &str = "DigestValue";
pub const SIGNATURE_METHOD_ELEMENT: &str = "SignatureMethod";
pub const CANONICALIZATION_METHOD_ELEMENT: &str = "CanonicalizationMethod";
pub const DIGEST_METHOD_ELEMENT: &str = "DigestMethod";

/// XML attribute names
pub const ALGORITHM_ATTRIBUTE: &str = "Algorithm";

/// PEM tags for certificates
pub const PEM_CERTIFICATE_TAG: &str = "CERTIFICATE";
pub const PEM_X509_CERTIFICATE_TAG: &str = "X509 CERTIFICATE";
pub const PEM_TRUSTED_CERTIFICATE_TAG: &str = "TRUSTED CERTIFICATE";

/// PEM tags for private keys
pub const PEM_PRIVATE_KEY_TAG: &str = "PRIVATE KEY";
pub const PEM_RSA_PRIVATE_KEY_TAG: &str = "RSA PRIVATE KEY";
pub const PEM_DSA_PRIVATE_KEY_TAG: &str = "DSA PRIVATE KEY";
pub const PEM_EC_PRIVATE_KEY_TAG: &str = "EC PRIVATE KEY";
pub const PEM_ENCRYPTED_PRIVATE_KEY_TAG: &str = "ENCRYPTED PRIVATE KEY";

/// SOAP element names
pub const SOAP_BODY_END_TAG: &str = "</soap:Body>";
pub const BODY_END_TAG: &str = "</Body>";
