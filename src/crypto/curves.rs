use crate::crypto::errors::CryptoResult;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use std::fmt;

/// Supported elliptic curves for eID operations
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (secp256r1)
    NistP256,
    /// NIST P-384 (secp384r1)
    NistP384,
    /// NIST P-521 (secp521r1)
    NistP521,
    /// Brainpool P-256r1
    #[default]
    BrainpoolP256r1,
    /// Brainpool P-384r1
    BrainpoolP384r1,
    /// Brainpool P-512r1
    BrainpoolP512r1,
}

impl Curve {
    /// Get the OpenSSL NID for this curve
    pub fn to_nid(self) -> Nid {
        match self {
            Curve::NistP256 => Nid::X9_62_PRIME256V1,
            Curve::NistP384 => Nid::SECP384R1,
            Curve::NistP521 => Nid::SECP521R1,
            Curve::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            Curve::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
            Curve::BrainpoolP512r1 => Nid::BRAINPOOL_P512R1,
        }
    }

    /// Create an OpenSSL EcGroup for this curve
    pub fn to_ec_group(self) -> CryptoResult<EcGroup> {
        Ok(EcGroup::from_curve_name(self.to_nid())?)
    }

    /// Get the key size in bytes for this curve
    pub fn key_size(self) -> usize {
        match self {
            Curve::NistP256 | Curve::BrainpoolP256r1 => 32,
            Curve::NistP384 | Curve::BrainpoolP384r1 => 48,
            Curve::NistP521 => 66,
            Curve::BrainpoolP512r1 => 64,
        }
    }

    /// Get the coordinate size in bytes
    pub fn coordinate_size(self) -> usize {
        self.key_size()
    }

    /// Get the uncompressed point size in bytes
    pub fn uncompressed_point_size(self) -> usize {
        1 + 2 * self.key_size()
    }

    /// Get the signature size in bytes
    pub fn signature_size(self) -> usize {
        2 * self.key_size()
    }

    /// Check if this is a NIST curve
    pub fn is_nist_curve(self) -> bool {
        matches!(self, Curve::NistP256 | Curve::NistP384 | Curve::NistP521)
    }

    /// Check if this is a Brainpool curve
    pub fn is_brainpool_curve(self) -> bool {
        matches!(
            self,
            Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 | Curve::BrainpoolP512r1
        )
    }

    /// Get the security level in bits
    pub fn security_level_bits(self) -> u32 {
        match self {
            Curve::NistP256 | Curve::BrainpoolP256r1 => 128,
            Curve::NistP384 | Curve::BrainpoolP384r1 => 192,
            Curve::NistP521 | Curve::BrainpoolP512r1 => 256,
        }
    }

    /// Get all supported curves
    pub fn all() -> &'static [Curve] {
        &[
            Curve::NistP256,
            Curve::NistP384,
            Curve::NistP521,
            Curve::BrainpoolP256r1,
            Curve::BrainpoolP384r1,
            Curve::BrainpoolP512r1,
        ]
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Curve::NistP256 => "NIST P-256 (secp256r1)",
            Curve::NistP384 => "NIST P-384 (secp384r1)",
            Curve::NistP521 => "NIST P-521 (secp521r1)",
            Curve::BrainpoolP256r1 => "Brainpool P-256r1",
            Curve::BrainpoolP384r1 => "Brainpool P-384r1",
            Curve::BrainpoolP512r1 => "Brainpool P-512r1",
        };
        write!(f, "{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_properties() {
        for &curve in Curve::all() {
            // Test that we can create an EC group
            assert!(curve.to_ec_group().is_ok());

            // Test key sizes are reasonable
            assert!(curve.key_size() >= 32);
            assert!(curve.key_size() <= 66);

            // Test security levels
            assert!(curve.security_level_bits() >= 128);
        }
    }

    #[test]
    fn test_curve_classification() {
        assert!(Curve::NistP256.is_nist_curve());
        assert!(!Curve::NistP256.is_brainpool_curve());

        assert!(Curve::BrainpoolP256r1.is_brainpool_curve());
        assert!(!Curve::BrainpoolP256r1.is_nist_curve());
    }
}
