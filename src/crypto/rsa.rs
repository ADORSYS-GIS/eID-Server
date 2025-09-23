use crate::crypto::HashAlg;
use crate::crypto::errors::{CryptoResult, Error};
use crate::crypto::keys::SecureBytes;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fmt;

/// RSA key sizes supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    /// 2048-bit RSA key
    Rsa2048,
    /// 3072-bit RSA key
    Rsa3072,
    /// 4096-bit RSA key
    Rsa4096,
}

impl RsaKeySize {
    /// Get the key size in bits
    pub fn bits(&self) -> u32 {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        }
    }

    /// Get the key size in bytes
    pub fn bytes(&self) -> u32 {
        self.bits() / 8
    }

    /// Get all supported key sizes
    pub fn all() -> &'static [RsaKeySize] {
        &[
            RsaKeySize::Rsa2048,
            RsaKeySize::Rsa3072,
            RsaKeySize::Rsa4096,
        ]
    }
}

impl TryFrom<u32> for RsaKeySize {
    type Error = Error;

    fn try_from(bits: u32) -> Result<Self, Self::Error> {
        match bits {
            2048 => Ok(Self::Rsa2048),
            3072 => Ok(Self::Rsa3072),
            4096 => Ok(Self::Rsa4096),
            _ => Err(Error::Invalid("Unsupported RSA key size".into())),
        }
    }
}

/// Represents an RSA signature
#[derive(Clone)]
pub struct RsaSignature {
    key_size: RsaKeySize,
    data: SecureBytes,
}

impl RsaSignature {
    /// Create a new RSA signature
    pub fn new(key_size: RsaKeySize, data: impl Into<Vec<u8>>) -> Self {
        Self {
            key_size,
            data: SecureBytes::new(data.into()),
        }
    }

    /// Get the key size used for this signature
    pub fn key_size(&self) -> RsaKeySize {
        self.key_size
    }

    /// Get the signature data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.data.expose_secret()
    }

    /// Convert signature to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.data.expose_secret())
    }

    /// Get the signature length in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for RsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSignature")
            .field("key_size", &self.key_size)
            .field("size", &self.len())
            .field("hex", &self.to_hex())
            .finish()
    }
}

/// RSA private key wrapper
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    key: PKey<Private>,
    key_size: RsaKeySize,
}

impl RsaPrivateKey {
    /// Generate a new RSA private key
    pub fn generate(key_size: RsaKeySize) -> CryptoResult<Self> {
        let rsa = Rsa::generate(key_size.bits())?;
        let key = PKey::from_rsa(rsa)?;

        Ok(Self { key, key_size })
    }

    /// Load from PEM-encoded PKCS#1/PKCS#8.
    pub fn from_pem(pem_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let key = PKey::private_key_from_pem(pem_bytes.as_ref())?;
        Self::from_pkey(key)
    }

    /// Load from DER-encoded PKCS#1/PKCS#8.
    pub fn from_der(der_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let key = PKey::private_key_from_der(der_bytes.as_ref())?;
        Self::from_pkey(key)
    }

    fn from_pkey(key: PKey<Private>) -> CryptoResult<Self> {
        let rsa = key.rsa()?;
        let bits = rsa.size() * 8;
        let key_size = RsaKeySize::try_from(bits as u32)?;
        Ok(Self { key, key_size })
    }

    /// Serialize as DER-encoded PKCS#8.
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.key.private_key_to_pkcs8()?)
    }

    /// Serialize as PEM-encoded PKCS#8.
    pub fn to_pem(&self) -> CryptoResult<String> {
        let pem_bytes = self.key.private_key_to_pem_pkcs8()?;
        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> CryptoResult<RsaPublicKey> {
        let pub_key = PKey::public_key_from_der(&self.key.public_key_to_der()?)?;

        Ok(RsaPublicKey {
            key: pub_key,
            key_size: self.key_size,
        })
    }

    /// Get the key size
    pub fn key_size(&self) -> RsaKeySize {
        self.key_size
    }

    /// Get the underlying OpenSSL private key
    pub(crate) fn pkey(&self) -> &PKey<Private> {
        &self.key
    }
}

/// RSA public key wrapper
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    key: PKey<Public>,
    key_size: RsaKeySize,
}

impl RsaPublicKey {
    /// Export key in SubjectPublicKeyInfo DER format
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.key.public_key_to_der()?)
    }

    /// Export key in SubjectPublicKeyInfo PEM format
    pub fn to_pem(&self) -> CryptoResult<String> {
        let pem_bytes = self.key.public_key_to_pem()?;
        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }

    /// Get the key size
    pub fn key_size(&self) -> RsaKeySize {
        self.key_size
    }

    /// Get the underlying OpenSSL public key
    pub(crate) fn pkey(&self) -> &PKey<Public> {
        &self.key
    }
}

/// An RSA key pair
#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair
    pub fn generate(key_size: RsaKeySize) -> CryptoResult<Self> {
        let private_key = RsaPrivateKey::generate(key_size)?;
        let public_key = private_key.public_key()?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create from existing private key
    pub fn from_private_key(private_key: RsaPrivateKey) -> CryptoResult<Self> {
        let public_key = private_key.public_key()?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Sign data with this key pair and return the signature
    pub fn sign(&self, data: impl AsRef<[u8]>, hash_alg: HashAlg) -> CryptoResult<RsaSignature> {
        sign(&self.private_key, data, hash_alg)
    }

    /// Verify a signature against data using this key pair
    pub fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: &RsaSignature,
        hash_alg: HashAlg,
    ) -> CryptoResult<bool> {
        verify(&self.public_key, data, signature, hash_alg)
    }

    /// Get the private key of this key pair
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Get the public key of this key pair
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Get the key size used by this key pair
    pub fn key_size(&self) -> RsaKeySize {
        self.private_key.key_size()
    }
}

/// Sign data using RSA private key
pub fn sign(
    private_key: &RsaPrivateKey,
    data: impl AsRef<[u8]>,
    hash_alg: HashAlg,
) -> CryptoResult<RsaSignature> {
    let digest = hash_alg.hash(data.as_ref())?;
    let mut signer = Signer::new_without_digest(private_key.pkey())?;
    let signature_data = signer.sign_oneshot_to_vec(&digest)?;

    Ok(RsaSignature::new(private_key.key_size(), signature_data))
}

/// Verify RSA signature
pub fn verify(
    public_key: &RsaPublicKey,
    data: impl AsRef<[u8]>,
    signature: &RsaSignature,
    hash_alg: HashAlg,
) -> CryptoResult<bool> {
    if public_key.key_size() != signature.key_size() {
        return Err(Error::Invalid(
            "Signature key size does not match key size".to_string(),
        ));
    }

    let digest = hash_alg.hash(data.as_ref())?;
    let mut verifier = Verifier::new_without_digest(public_key.pkey())?;
    let result = verifier.verify_oneshot(signature.as_bytes(), &digest)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_pair_generation() {
        for &key_size in RsaKeySize::all() {
            let key_pair = RsaKeyPair::generate(key_size).unwrap();
            assert_eq!(key_pair.key_size(), key_size);
            assert_eq!(key_pair.private_key().key_size(), key_size);
            assert_eq!(key_pair.public_key().key_size(), key_size);
        }
    }

    #[test]
    fn test_rsa_sign_verify() {
        let key_size = RsaKeySize::Rsa2048;
        let key_pair = RsaKeyPair::generate(key_size).unwrap();
        let data = b"test data";
        let hash_alg = HashAlg::Sha256;

        // Test signing and verification
        let signature = key_pair.sign(data, hash_alg).unwrap();
        assert_eq!(signature.key_size(), key_size);

        let is_valid = key_pair.verify(data, &signature, hash_alg).unwrap();
        assert!(is_valid);

        // Test with wrong data
        let wrong_data = b"wrong data";
        let result = key_pair.verify(wrong_data, &signature, hash_alg);
        assert!(result.is_ok());
        let is_valid = result.unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_key_roundtrip() {
        // load via PEM
        let pem_bytes = include_bytes!("../../test_data/rsa/rsa4096.pem");
        let result = RsaPrivateKey::from_pem(&pem_bytes);
        assert!(result.is_ok());
        let pk_pem = result.unwrap();

        // load via DER
        let der_bytes = include_bytes!("../../test_data/rsa/rsa4096.der");
        let result = RsaPrivateKey::from_der(&der_bytes);
        assert!(result.is_ok());
        let pk_der = result.unwrap();

        // Both must produce identical DER and PEM
        assert_eq!(pk_pem.to_der().unwrap(), pk_der.to_der().unwrap());
        assert_eq!(pk_pem.to_pem().unwrap(), pk_der.to_pem().unwrap());

        // serializing must produce identical DER
        assert_eq!(pk_pem.to_der().unwrap(), der_bytes);

        let pub_pem = pk_pem.public_key().unwrap();
        assert_eq!(pub_pem.key_size(), pk_pem.key_size());
    }

    #[test]
    fn test_signature_debug_format() {
        let key_size = RsaKeySize::Rsa2048;
        let key_pair = RsaKeyPair::generate(key_size).unwrap();
        let data = b"test data";
        let hash_alg = HashAlg::Sha256;

        let signature = key_pair.sign(data, hash_alg).unwrap();
        let debug_str = format!("{:?}", signature);

        assert!(debug_str.contains("RsaSignature"));
        assert!(debug_str.contains("Rsa2048"));
        assert!(debug_str.contains("size"));
        assert!(debug_str.contains("hex"));
    }

    #[test]
    fn test_cross_key_verification_fails() {
        let key_pair1 = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let key_pair2 = RsaKeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let data = b"test data";
        let hash_alg = HashAlg::Sha256;

        let signature = key_pair1.sign(data, hash_alg).unwrap();
        let is_valid = key_pair2.verify(data, &signature, hash_alg).unwrap();
        assert!(!is_valid);
    }
}
