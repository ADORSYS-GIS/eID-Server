pub mod ecdh;
pub mod ecdsa;

mod errors;

// public re-exports
pub use errors::Error;

use openssl::hash::{Hasher, MessageDigest as Digest};

type CryptoResult<T> = Result<T, Error>;

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Get the OpenSSL MessageDigest for this hash algorithm
    pub fn message_digest(&self) -> Digest {
        match self {
            HashAlg::Sha1 => Digest::sha1(),
            HashAlg::Sha224 => Digest::sha224(),
            HashAlg::Sha256 => Digest::sha256(),
            HashAlg::Sha384 => Digest::sha384(),
            HashAlg::Sha512 => Digest::sha512(),
        }
    }

    /// Hash the given data with this hash algorithm
    pub fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Hasher::new(self.message_digest())?;
        hasher.update(data)?;
        Ok(hasher.finish()?.to_vec())
    }
}
