use crate::crypto::HashAlg;
use crate::asn1::oid::*;

use super::Error;
use super::types::CvcResult;

use rasn::types::ObjectIdentifier as Oid;

/// Security protocols supported by CV certificates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityProtocol {
    /// RSA v1.5 + SHA-1
    RsaV1_5Sha1,
    /// RSA v1.5 + SHA-256
    RsaV1_5Sha256,
    /// RSA-PSS + SHA-1
    RsaPssSha1,
    /// RSA-PSS + SHA-256
    RsaPssSha256,
    /// RSA v1.5 + SHA-512
    RsaV1_5Sha512,
    /// RSA-PSS + SHA-512
    RsaPssSha512,
    /// ECDSA + SHA-1
    EcdsaSha1,
    /// ECDSA + SHA-224
    EcdsaSha224,
    /// ECDSA + SHA-256
    EcdsaSha256,
    /// ECDSA + SHA-384
    EcdsaSha384,
    /// ECDSA + SHA-512
    EcdsaSha512,
}

impl SecurityProtocol {
    /// Build a security protocol from the OID string
    pub fn from_oid(oid: &str) -> CvcResult<Self> {
        match oid {
            RSA_SHA1_OID_STR => Ok(SecurityProtocol::RsaV1_5Sha1),
            RSA_SHA256_OID_STR => Ok(SecurityProtocol::RsaV1_5Sha256),
            RSA_SHA512_OID_STR => Ok(SecurityProtocol::RsaV1_5Sha512),
            RSA_PSS_SHA1_OID_STR => Ok(SecurityProtocol::RsaPssSha1),
            RSA_PSS_SHA256_OID_STR => Ok(SecurityProtocol::RsaPssSha256),
            RSA_PSS_SHA512_OID_STR => Ok(SecurityProtocol::RsaPssSha512),
            ECDSA_SHA1_OID_STR => Ok(SecurityProtocol::EcdsaSha1),
            ECDSA_SHA224_OID_STR => Ok(SecurityProtocol::EcdsaSha224),
            ECDSA_SHA256_OID_STR => Ok(SecurityProtocol::EcdsaSha256),
            ECDSA_SHA384_OID_STR => Ok(SecurityProtocol::EcdsaSha384),
            ECDSA_SHA512_OID_STR => Ok(SecurityProtocol::EcdsaSha512),
            other => Err(Error::UnsupportedProtocol(other.to_string())),
        }
    }

    /// Get the OID for this security protocol
    pub fn oid(&self) -> Oid {
        match self {
            SecurityProtocol::RsaV1_5Sha1 => Oid::new_unchecked(RSA_SHA1_OID.into()),
            SecurityProtocol::RsaV1_5Sha256 => Oid::new_unchecked(RSA_SHA256_OID.into()),
            SecurityProtocol::RsaPssSha1 => Oid::new_unchecked(RSA_PSS_SHA1_OID.into()),
            SecurityProtocol::RsaPssSha256 => Oid::new_unchecked(RSA_PSS_SHA256_OID.into()),
            SecurityProtocol::RsaV1_5Sha512 => Oid::new_unchecked(RSA_SHA512_OID.into()),
            SecurityProtocol::RsaPssSha512 => Oid::new_unchecked(RSA_PSS_SHA512_OID.into()),
            SecurityProtocol::EcdsaSha1 => Oid::new_unchecked(ECDSA_SHA1_OID.into()),
            SecurityProtocol::EcdsaSha224 => Oid::new_unchecked(ECDSA_SHA224_OID.into()),
            SecurityProtocol::EcdsaSha256 => Oid::new_unchecked(ECDSA_SHA256_OID.into()),
            SecurityProtocol::EcdsaSha384 => Oid::new_unchecked(ECDSA_SHA384_OID.into()),
            SecurityProtocol::EcdsaSha512 => Oid::new_unchecked(ECDSA_SHA512_OID.into()),
        }
    }

    /// Get the hash algorithm for this protocol
    pub fn hash_algorithm(&self) -> HashAlg {
        match self {
            SecurityProtocol::RsaV1_5Sha1
            | SecurityProtocol::RsaPssSha1
            | SecurityProtocol::EcdsaSha1 => HashAlg::Sha1,

            SecurityProtocol::EcdsaSha224 => HashAlg::Sha224,

            SecurityProtocol::RsaV1_5Sha256
            | SecurityProtocol::RsaPssSha256
            | SecurityProtocol::EcdsaSha256 => HashAlg::Sha256,

            SecurityProtocol::EcdsaSha384 => HashAlg::Sha384,

            SecurityProtocol::RsaV1_5Sha512
            | SecurityProtocol::RsaPssSha512
            | SecurityProtocol::EcdsaSha512 => HashAlg::Sha512,
        }
    }

    /// Check if this is an ECDSA protocol
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            SecurityProtocol::EcdsaSha1
                | SecurityProtocol::EcdsaSha224
                | SecurityProtocol::EcdsaSha256
                | SecurityProtocol::EcdsaSha384
                | SecurityProtocol::EcdsaSha512
        )
    }

    /// Check if this is an RSA protocol
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            SecurityProtocol::RsaV1_5Sha1
                | SecurityProtocol::RsaV1_5Sha256
                | SecurityProtocol::RsaPssSha1
                | SecurityProtocol::RsaPssSha256
                | SecurityProtocol::RsaV1_5Sha512
                | SecurityProtocol::RsaPssSha512
        )
    }
}

impl std::fmt::Display for SecurityProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Algorithm: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_protocol_from_oid() {
        assert_eq!(
            SecurityProtocol::from_oid(RSA_SHA256_OID_STR).unwrap(),
            SecurityProtocol::RsaV1_5Sha256
        );
        assert_eq!(
            SecurityProtocol::from_oid(ECDSA_SHA256_OID_STR).unwrap(),
            SecurityProtocol::EcdsaSha256
        );
    }

    #[test]
    fn test_security_protocol_hash_algorithm() {
        assert_eq!(
            SecurityProtocol::RsaV1_5Sha256.hash_algorithm(),
            HashAlg::Sha256
        );
        assert_eq!(
            SecurityProtocol::RsaV1_5Sha512.hash_algorithm(),
            HashAlg::Sha512
        );
        assert_eq!(
            SecurityProtocol::RsaPssSha256.hash_algorithm(),
            HashAlg::Sha256
        );
        assert_eq!(
            SecurityProtocol::RsaPssSha512.hash_algorithm(),
            HashAlg::Sha512
        );
        assert_eq!(
            SecurityProtocol::EcdsaSha256.hash_algorithm(),
            HashAlg::Sha256
        );
        assert_eq!(
            SecurityProtocol::EcdsaSha384.hash_algorithm(),
            HashAlg::Sha384
        );
        assert_eq!(
            SecurityProtocol::EcdsaSha512.hash_algorithm(),
            HashAlg::Sha512
        );
    }

    #[test]
    fn test_security_protocol_is_ecdsa() {
        assert!(SecurityProtocol::EcdsaSha256.is_ecdsa());
        assert!(SecurityProtocol::EcdsaSha384.is_ecdsa());
        assert!(SecurityProtocol::EcdsaSha512.is_ecdsa());
        assert!(!SecurityProtocol::RsaV1_5Sha256.is_ecdsa());
        assert!(!SecurityProtocol::RsaPssSha256.is_ecdsa());
    }

    #[test]
    fn test_security_protocol_is_rsa() {
        assert!(SecurityProtocol::RsaV1_5Sha256.is_rsa());
        assert!(SecurityProtocol::RsaPssSha256.is_rsa());
        assert!(!SecurityProtocol::EcdsaSha256.is_rsa());
    }
}
