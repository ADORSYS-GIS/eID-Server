//! List of Known Object Identifiers (OIDs) used in the eID-Server.

// Certificate Holder Authorization Template (CHAT) object identifier
pub const CHAT_OID_STR: &str = "0.4.0.127.0.7.3.1.2.2";
pub const CHAT_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 2, 2];

// OIDs for security protocols supported by CV certificates
pub const RSA_SHA1_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.1";
pub const RSA_SHA256_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.2";
pub const RSA_SHA512_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.5";
pub const RSA_PSS_SHA1_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.3";
pub const RSA_PSS_SHA256_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.4";
pub const RSA_PSS_SHA512_OID_STR: &str = "0.4.0.127.0.7.2.2.2.1.6";
pub const ECDSA_SHA1_OID_STR: &str = "0.4.0.127.0.7.2.2.2.2.1";
pub const ECDSA_SHA224_OID_STR: &str = "0.4.0.127.0.7.2.2.2.2.2";
pub const ECDSA_SHA256_OID_STR: &str = "0.4.0.127.0.7.2.2.2.2.3";
pub const ECDSA_SHA384_OID_STR: &str = "0.4.0.127.0.7.2.2.2.2.4";
pub const ECDSA_SHA512_OID_STR: &str = "0.4.0.127.0.7.2.2.2.2.5";
pub const RSA_SHA1_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 1];
pub const RSA_SHA256_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 2];
pub const RSA_SHA512_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 5];
pub const RSA_PSS_SHA1_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 3];
pub const RSA_PSS_SHA256_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 4];
pub const RSA_PSS_SHA512_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 6];
pub const ECDSA_SHA1_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 1];
pub const ECDSA_SHA224_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 2];
pub const ECDSA_SHA256_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 3];
pub const ECDSA_SHA384_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 4];
pub const ECDSA_SHA512_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 5];

// OIDs for certificate description formats
pub const PLAIN_FORMAT_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 3, 1, 1];
pub const HTML_FORMAT_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 3, 1, 2];
pub const PDF_FORMAT_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 3, 1, 3];

// OIDs for authenticated auxiliary data
pub const DATE_OF_BIRTH_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 4, 1];
pub const DATE_OF_EXPIRY_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 4, 2];
pub const MUNICIPALITY_ID_OID: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 1, 4, 3];
