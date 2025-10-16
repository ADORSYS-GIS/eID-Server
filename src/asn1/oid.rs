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

// OIDs for Chip Authentication protocol
pub const ID_CA_ECDH: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 3, 2];
pub const ID_PK_ECDH: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 1, 2];
pub const ID_CA_ECDH_AES_CBC_CMAC_128: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 2];
pub const ID_CA_ECDH_AES_CBC_CMAC_192: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 3];
pub const ID_CA_ECDH_AES_CBC_CMAC_256: &[u32] = &[0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 4];
pub const STD_DOMAINPARAMS: &[u32] = &[0, 4, 0, 127, 0, 7, 1, 2];

// OIDs for Cryptographic Message Syntax (CMS)
pub const ID_SIGNED_DATA: &[u32] = &[1, 2, 840, 113549, 1, 7, 2];
pub const ID_SECURITY_OBJECT: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 1];

// OIDs for hash algorithms
pub const SHA256_OID: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
pub const SHA384_OID: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
pub const SHA512_OID: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];

// OIDs for mobile eIDs
pub const ID_EID_TYPE: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3];
pub const ID_CARD_EID_TYPE: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3, 1];
pub const ID_MOBILE_EID_TYPE: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3, 2];
pub const EID_TYPE_SE_CERTIFIED: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3, 2, 1];
pub const EID_TYPE_SE_ENDORSED: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3, 2, 2];
pub const EID_TYPE_HW_KEYSTORE: &[u32] = &[0, 4, 0, 127, 0, 7, 3, 2, 3, 2, 3];
