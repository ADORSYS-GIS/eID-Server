use crate::crypto::curves::Curve;
use crate::crypto::errors::{CryptoResult, Error};
use crate::crypto::keys::{PrivateKey, PublicKey, SecureBytes};
use openssl::derive::Deriver;
use std::fmt;

/// ECDH key pair for key agreement operations
#[derive(Clone)]
pub struct EcdhKeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl EcdhKeyPair {
    /// Generate a new ECDH key pair
    pub fn generate(curve: Curve) -> CryptoResult<Self> {
        let private_key = PrivateKey::generate(curve)?;
        let public_key = private_key.public_key()?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Generate an ephemeral key pair for one-time use
    pub fn generate_ephemeral(curve: Curve) -> CryptoResult<Self> {
        Self::generate(curve)
    }

    /// Create from existing private key
    pub fn from_private_key(private_key: PrivateKey) -> CryptoResult<Self> {
        let public_key = private_key.public_key()?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Perform ECDH key agreement with a peer's public key
    pub fn key_agreement(&self, peer_public_key: &PublicKey) -> CryptoResult<SharedSecret> {
        key_agreement(&self.private_key, peer_public_key)
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

impl fmt::Debug for EcdhKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdhKeyPair")
            .field("curve", &self.curve())
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Shared secret result from ECDH key agreement
#[derive(Clone, Default)]
pub struct SharedSecret {
    curve: Curve,
    secret_data: SecureBytes,
}

impl SharedSecret {
    /// Create a new shared secret
    pub(crate) fn new(curve: Curve, secret_data: impl Into<Vec<u8>>) -> Self {
        Self {
            curve,
            secret_data: SecureBytes::new(secret_data.into()),
        }
    }

    /// Get the curve used for this shared secret
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// Expose the raw shared secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.secret_data.expose_secret()
    }

    /// Get the length of the shared secret
    pub fn len(&self) -> usize {
        self.secret_data.len()
    }

    /// Check if the shared secret is empty
    pub fn is_empty(&self) -> bool {
        self.secret_data.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.secret_data.to_hex()
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("curve", &self.curve)
            .field("length", &self.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Perform ECDH key agreement using separate private and public keys
pub fn key_agreement(
    private_key: &PrivateKey,
    peer_public_key: &PublicKey,
) -> CryptoResult<SharedSecret> {
    // Validate curve compatibility
    if private_key.curve() != peer_public_key.curve() {
        return Err(Error::Invalid("Key curves do not match".to_string()));
    }
    // Perform ECDH key agreement
    let mut deriver = Deriver::new(private_key.as_openssl_pkey())?;
    deriver.set_peer(peer_public_key.as_openssl_pkey())?;

    let shared_secret_bytes = deriver.derive_to_vec()?;
    Ok(SharedSecret::new(private_key.curve(), shared_secret_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_key_pair_generation() {
        for &curve in Curve::all() {
            let key_pair = EcdhKeyPair::generate(curve).unwrap();
            assert_eq!(key_pair.curve(), curve);
            assert_eq!(key_pair.private_key().curve(), curve);
            assert_eq!(key_pair.public_key().curve(), curve);
        }
    }

    #[test]
    fn test_ecdh_key_agreement() {
        for &curve in Curve::all() {
            let alice_keypair = EcdhKeyPair::generate(curve).unwrap();
            let bob_keypair = EcdhKeyPair::generate(curve).unwrap();

            // Perform key agreement from both sides
            let alice_shared = alice_keypair
                .key_agreement(bob_keypair.public_key())
                .unwrap();
            let bob_shared = bob_keypair
                .key_agreement(alice_keypair.public_key())
                .unwrap();

            // Shared secrets should be equal
            assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        }
    }

    #[test]
    fn test_ecdh_standalone_operations() {
        let curve = Curve::BrainpoolP256r1;
        let alice_private = PrivateKey::generate(curve).unwrap();
        let bob_private = PrivateKey::generate(curve).unwrap();
        let alice_public = alice_private.public_key().unwrap();
        let bob_public = bob_private.public_key().unwrap();

        // Perform standalone key agreement
        let alice_shared = key_agreement(&alice_private, &bob_public).unwrap();
        let bob_shared = key_agreement(&bob_private, &alice_public).unwrap();

        // Shared secrets should be equal
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_cross_curve_key_agreement_fails() {
        let alice_keypair = EcdhKeyPair::generate(Curve::NistP256).unwrap();
        let bob_keypair = EcdhKeyPair::generate(Curve::NistP384).unwrap();

        // This should fail because curves don't match
        let result = alice_keypair.key_agreement(bob_keypair.public_key());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Key curves do not match")
        );
    }
}
