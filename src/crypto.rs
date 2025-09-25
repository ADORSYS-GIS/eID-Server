mod curves;
pub mod ecdh;
pub mod ecdsa;
mod errors;
pub mod kdf;
mod keys;
pub mod rsa;
pub mod sym;
mod utils;

pub use curves::Curve;
pub use errors::Error;
pub use keys::{PrivateKey, PublicKey, SecureBytes};
pub use utils::*;

use errors::CryptoResult;
use openssl::hash::{Hasher, MessageDigest as Digest};
use std::fmt;

/// Hash algorithms supported for ECDSA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HashAlg {
    /// Hash the given data with this hash algorithm
    pub fn hash(&self, data: impl AsRef<[u8]>) -> CryptoResult<Vec<u8>> {
        let mut hasher = Hasher::new(self.into())?;
        hasher.update(data.as_ref())?;
        Ok(hasher.finish()?.to_vec())
    }

    /// Get the output size in bytes
    pub fn output_size(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha224 => 28,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
}

impl From<&HashAlg> for Digest {
    fn from(hash_alg: &HashAlg) -> Self {
        match hash_alg {
            HashAlg::Sha1 => Digest::sha1(),
            HashAlg::Sha224 => Digest::sha224(),
            HashAlg::Sha256 => Digest::sha256(),
            HashAlg::Sha384 => Digest::sha384(),
            HashAlg::Sha512 => Digest::sha512(),
        }
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha224 => "SHA-224",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
        };
        write!(f, "{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_data() {
        let data = b"test_data";

        assert!(HashAlg::Sha1.hash(data).is_ok());
        assert!(HashAlg::Sha256.hash(data).is_ok());
        assert!(HashAlg::Sha512.hash(data).is_ok());
    }
}
