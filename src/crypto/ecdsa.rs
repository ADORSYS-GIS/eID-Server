use crate::crypto::HashAlg;
use crate::crypto::curves::Curve;
use crate::crypto::errors::{CryptoResult, Error};
use crate::crypto::keys::{PrivateKey, PublicKey};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig as OpenSslEcdsaSig;
use openssl::sign::{Signer, Verifier};
use std::fmt;

/// ECDSA signature representation
#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaSig {
    // The curve used for this signature
    curve: Curve,
    // DER-encoded signature data
    der_data: Vec<u8>,
    // Raw signature components (r, s)
    raw_components: (Vec<u8>, Vec<u8>),
}

impl EcdsaSig {
    /// Create signature from DER-encoded signature data
    pub fn from_der(curve: Curve, der_data: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let ecdsa_sig = OpenSslEcdsaSig::from_der(der_data.as_ref())?;

        // Extract raw signature components (r, s)
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();

        Ok(Self {
            curve,
            der_data: der_data.as_ref().to_vec(),
            raw_components: (r, s),
        })
    }

    /// Create from hex string representation of DER encoded signature
    pub fn from_hex(curve: Curve, hex_str: &str) -> CryptoResult<Self> {
        let der_data = hex::decode(hex_str)?;
        Self::from_der(curve, der_data)
    }

    /// Create signature from raw r, s components
    pub fn from_components(curve: Curve, r: &[u8], s: &[u8]) -> CryptoResult<Self> {
        let r_bn = BigNum::from_slice(r)?;
        let s_bn = BigNum::from_slice(s)?;
        let ecdsa_sig = OpenSslEcdsaSig::from_private_components(r_bn, s_bn)?;
        let der_data = ecdsa_sig.to_der()?;

        Ok(Self {
            curve,
            der_data,
            raw_components: (r.to_vec(), s.to_vec()),
        })
    }

    /// Get the curve used for this signature
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// Get DER-encoded signature data
    pub fn as_der(&self) -> &[u8] {
        &self.der_data
    }

    /// Get raw concatenated signature components r || s
    pub fn raw_signature(&self) -> CryptoResult<Vec<u8>> {
        let (r, s) = &self.raw_components;
        let mut combined = Vec::with_capacity(r.len() + s.len());
        combined.extend_from_slice(r);
        combined.extend_from_slice(s);
        Ok(combined)
    }

    /// Convert DER encoded signature to hex string representation
    pub fn to_hex(&self) -> String {
        hex::encode(&self.der_data)
    }

    /// Returns the hex representation of the raw signature components r || s
    pub fn raw_to_hex(&self) -> CryptoResult<String> {
        let combined = self.raw_signature()?;
        Ok(hex::encode(&combined))
    }

    /// Get the signature size in bytes
    pub fn size(&self) -> usize {
        self.der_data.len()
    }
}

impl fmt::Debug for EcdsaSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSig")
            .field("curve", &self.curve)
            .field("size", &self.der_data.len())
            .field("hex", &self.to_hex())
            .finish()
    }
}

/// ECDSA key pair for signature operations
#[derive(Clone)]
pub struct EcdsaKeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA key pair
    pub fn generate(curve: Curve) -> CryptoResult<Self> {
        let private_key = PrivateKey::generate(curve)?;
        let public_key = private_key.public_key()?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create from existing private key
    pub fn from_private_key(private_key: PrivateKey) -> CryptoResult<Self> {
        let public_key = private_key.public_key()?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Sign data with this key pair and return the signature
    pub fn sign(&self, data: impl AsRef<[u8]>, hash_alg: HashAlg) -> CryptoResult<EcdsaSig> {
        sign(&self.private_key, data, hash_alg)
    }

    /// Verify a signature against data using this key pair
    pub fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: &EcdsaSig,
        hash_alg: HashAlg,
    ) -> CryptoResult<bool> {
        verify(&self.public_key, data, signature, hash_alg)
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the curve used by this key pair
    pub fn curve(&self) -> Curve {
        self.private_key.curve()
    }
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("curve", &self.curve())
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Sign data with a private key and return the signature
pub fn sign(
    private_key: &PrivateKey,
    data: impl AsRef<[u8]>,
    hash_alg: HashAlg,
) -> CryptoResult<EcdsaSig> {
    let mut signer = Signer::new(hash_alg.into(), private_key.as_openssl_pkey())?;
    signer.update(data.as_ref())?;
    let signature_der = signer.sign_to_vec()?;

    EcdsaSig::from_der(private_key.curve(), signature_der)
}

/// Verify a signature against data using a public key
pub fn verify(
    public_key: &PublicKey,
    data: impl AsRef<[u8]>,
    signature: &EcdsaSig,
    hash_alg: HashAlg,
) -> CryptoResult<bool> {
    if signature.curve() != public_key.curve() {
        return Err(Error::Invalid(
            "Signature curve does not match key curve".to_string(),
        ));
    }

    let mut verifier = Verifier::new(hash_alg.into(), public_key.as_openssl_pkey())?;
    verifier.update(data.as_ref())?;
    let result = verifier.verify(signature.as_der())?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_key_pair_generation() {
        for &curve in Curve::all() {
            let key_pair = EcdsaKeyPair::generate(curve).unwrap();
            assert_eq!(key_pair.curve(), curve);
            assert_eq!(key_pair.private_key().curve(), curve);
            assert_eq!(key_pair.public_key().curve(), curve);
        }
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let curve = Curve::BrainpoolP256r1;
        let key_pair = EcdsaKeyPair::generate(curve).unwrap();
        let data = b"test data";
        let hash_alg = HashAlg::Sha256;

        // Test signing and verification
        let signature = key_pair.sign(data, hash_alg).unwrap();
        assert_eq!(signature.curve(), curve);

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
    fn test_ecdsa_standalone_operations() {
        let curve = Curve::BrainpoolP256r1;
        let private_key = PrivateKey::generate(curve).unwrap();
        let public_key = private_key.public_key().unwrap();
        let data = b"standalone ECDSA test";
        let hash_alg = HashAlg::Sha384;

        // Test standalone signing and verification
        let signature = sign(&private_key, data, hash_alg).unwrap();
        let is_valid = verify(&public_key, data, &signature, hash_alg).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signature_serialization() {
        let curve = Curve::BrainpoolP256r1;
        let key_pair = EcdsaKeyPair::generate(curve).unwrap();
        let data = b"serialization test";
        let hash_alg = HashAlg::Sha256;

        let signature = key_pair.sign(data, hash_alg).unwrap();

        // Test hex serialization
        let hex_str = signature.to_hex();
        let recovered_signature = EcdsaSig::from_hex(curve, &hex_str).unwrap();

        let is_valid = key_pair
            .verify(data, &recovered_signature, hash_alg)
            .unwrap();
        assert!(is_valid);

        // Test component extraction
        let raw_signature = signature.raw_signature().unwrap();
        let (r, s) = raw_signature.split_at(raw_signature.len() / 2);
        let reconstructed = EcdsaSig::from_components(curve, r, s).unwrap();

        let is_valid_reconstructed = key_pair.verify(data, &reconstructed, hash_alg).unwrap();
        assert!(is_valid_reconstructed);
    }

    #[test]
    fn test_cross_curve_verification_fails() {
        let key_pair_256 = EcdsaKeyPair::generate(Curve::NistP256).unwrap();
        let key_pair_384 = EcdsaKeyPair::generate(Curve::NistP384).unwrap();
        let data = b"cross-curve test";

        let signature_256 = key_pair_256.sign(data, HashAlg::Sha256).unwrap();

        // This should fail because curves don't match
        let result = key_pair_384.verify(data, &signature_256, HashAlg::Sha256);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Signature curve does not match key curve")
        );
    }
}
