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

/// PEM tags for public keys
pub const PEM_PUBLIC_KEY_TAG: &str = "PUBLIC KEY";
pub const PEM_RSA_PUBLIC_KEY_TAG: &str = "RSA PUBLIC KEY";
pub const PEM_DSA_PUBLIC_KEY_TAG: &str = "DSA PUBLIC KEY";
pub const PEM_EC_PUBLIC_KEY_TAG: &str = "EC PUBLIC KEY";

/// PEM tags for certificate requests
pub const PEM_CERTIFICATE_REQUEST_TAG: &str = "CERTIFICATE REQUEST";
pub const PEM_NEW_CERTIFICATE_REQUEST_TAG: &str = "NEW CERTIFICATE REQUEST";

/// PEM tags for certificate revocation lists
pub const PEM_X509_CRL_TAG: &str = "X509 CRL";
pub const PEM_CRL_TAG: &str = "CRL";

/// PEM tags for Diffie-Hellman parameters
pub const PEM_DH_PARAMETERS_TAG: &str = "DH PARAMETERS";
pub const PEM_X9_42_DH_PARAMETERS_TAG: &str = "X9.42 DH PARAMETERS";

/// PEM tags for DSA parameters
pub const PEM_DSA_PARAMETERS_TAG: &str = "DSA PARAMETERS";

/// PEM tags for elliptic curve parameters
pub const PEM_EC_PARAMETERS_TAG: &str = "EC PARAMETERS";

/// PEM tags for PKCS#7 structures
pub const PEM_PKCS7_TAG: &str = "PKCS7";
pub const PEM_PKCS7_SIGNED_DATA_TAG: &str = "PKCS7 SIGNED DATA";

/// PEM tags for SSH keys
pub const PEM_OPENSSH_PRIVATE_KEY_TAG: &str = "OPENSSH PRIVATE KEY";

/// PEM tags for other formats
pub const PEM_PARAMETERS_TAG: &str = "PARAMETERS";
pub const PEM_SSL_SESSION_PARAMETERS_TAG: &str = "SSL SESSION PARAMETERS";

/// SOAP element names
pub const SOAP_BODY_END_TAG: &str = "</soap:Body>";
pub const BODY_END_TAG: &str = "</Body>";
