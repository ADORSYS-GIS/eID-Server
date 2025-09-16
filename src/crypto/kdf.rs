use crate::crypto::HashAlg;
use crate::crypto::ecdh::SharedSecret;
use crate::crypto::errors::CryptoResult;
use crate::crypto::keys::SecureBytes;

/// Parameters for key derivation operations
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// Hash function to use
    pub hash_function: HashAlg,
    /// Nonce bytes
    pub nonce: Option<Vec<u8>>,
    /// Counter value
    pub counter: Option<u32>,
    /// Output key length in bytes
    pub output_length: usize,
}

impl KdfParams {
    /// Create new KDF parameters with defaults
    pub fn new(hash_function: HashAlg, output_length: usize) -> Self {
        Self {
            hash_function,
            nonce: None,
            counter: None,
            output_length,
        }
    }

    /// Set the nonce bytes to use with the KDF
    pub fn with_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set the counter value to use with the KDF
    pub fn with_counter(mut self, counter: u32) -> Self {
        self.counter = Some(counter);
        self
    }
}

/// Derive a key from given bytes and parameters
pub fn derive_key(bytes: impl AsRef<[u8]>, params: &KdfParams) -> CryptoResult<SecureBytes> {
    let mut input = Vec::new();
    input.extend_from_slice(bytes.as_ref());
    if let Some(nonce) = params.nonce.as_ref() {
        input.extend_from_slice(nonce);
    }
    if let Some(counter) = params.counter {
        input.extend_from_slice(&counter.to_be_bytes());
    }

    let mut hash_data = params.hash_function.hash(&input)?;
    hash_data.truncate(params.output_length);
    Ok(SecureBytes::new(hash_data))
}

/// Derive a key from a shared secret and given parameters
pub fn derive_from_shared_secret(
    shared_secret: &SharedSecret,
    params: &KdfParams,
) -> CryptoResult<SecureBytes> {
    derive_key(shared_secret.as_bytes(), params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let params = KdfParams::new(HashAlg::Sha256, 32);
        let derived_key = derive_key(b"test input", &params).unwrap();
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_derive_from_shared_secret() {
        let shared_secret = SharedSecret::default();
        let params = KdfParams::new(HashAlg::Sha256, 32);
        let derived_key = derive_from_shared_secret(&shared_secret, &params).unwrap();
        assert_eq!(derived_key.len(), 32);
    }
}
