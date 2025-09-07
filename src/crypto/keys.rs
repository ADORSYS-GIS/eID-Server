use crate::crypto::curves::Curve;
use crate::crypto::errors::{CryptoResult, Error};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcKey, EcPoint, PointConversionForm as Form};
use openssl::pkey::{PKey, Private, Public};
use secrecy::{ExposeSecret, SecretSlice};
use std::fmt;

/// Secure wrapper for sensitive byte data that zeroizes on drop
#[derive(Debug, Clone, Default)]
pub struct SecureBytes(SecretSlice<u8>);

impl SecureBytes {
    /// Create new SecureBytes
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self(SecretSlice::new(data.into().into()))
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> CryptoResult<Self> {
        let data = hex::decode(hex_str)?;
        Ok(Self::new(data))
    }

    /// Expose the secret data
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Check if the data is empty
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }

    /// Returns the hex representation of the data
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.expose_secret())
    }
}

/// Represents a private key
#[derive(Clone)]
pub struct PrivateKey {
    curve: Curve,
    key_data: SecureBytes,
    openssl_key: PKey<Private>,
}

impl PrivateKey {
    /// Generate a new random private key with the given curve
    pub fn generate(curve: Curve) -> CryptoResult<Self> {
        let group = curve.to_ec_group()?;
        let ec_key = EcKey::generate(&group)?;
        let private_key_bn = ec_key.private_key();
        let key_bytes = private_key_bn.to_vec();

        let mut padded_bytes = vec![0u8; curve.key_size()];
        let start_idx = curve.key_size().saturating_sub(key_bytes.len());
        padded_bytes[start_idx..].copy_from_slice(&key_bytes);

        let pkey = PKey::from_ec_key(ec_key)?;

        Ok(Self {
            curve,
            key_data: SecureBytes::new(padded_bytes),
            openssl_key: pkey,
        })
    }

    /// Create a new private key from bytes components
    pub fn from_bytes(
        curve: Curve,
        key_bytes: impl AsRef<[u8]>,
        public_point: impl AsRef<[u8]>,
    ) -> CryptoResult<Self> {
        if key_bytes.as_ref().len() != curve.key_size() {
            return Err(Error::Invalid(format!(
                "Invalid key size: expected {} bytes, got {}",
                curve.key_size(),
                key_bytes.as_ref().len()
            )));
        }

        let group = curve.to_ec_group()?;
        let d = BigNum::from_slice(key_bytes.as_ref())?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, public_point.as_ref(), &mut ctx)?;
        let ec_key = EcKey::from_private_components(&group, &d, &point)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        Ok(Self {
            curve,
            key_data: SecureBytes::new(key_bytes.as_ref().to_vec()),
            openssl_key: pkey,
        })
    }

    /// Import key from PKCS#8 PEM format
    pub fn from_pkcs8_pem(pem_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let pkey = PKey::private_key_from_pem(pem_bytes.as_ref())?;
        Self::pk_to_private(pkey)
    }

    /// Import key from PKCS#8 DER format
    pub fn from_pkcs8_der(der_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let pkey = PKey::private_key_from_der(der_bytes.as_ref())?;
        Self::pk_to_private(pkey)
    }

    fn pk_to_private(pk: PKey<Private>) -> CryptoResult<Self> {
        let ec_key = pk.ec_key()?;
        let group = ec_key.group();

        // Determine curve from the group
        let curve = Curve::all()
            .iter()
            .find(|&&c| {
                c.to_ec_group()
                    .map(|g| g.curve_name() == group.curve_name())
                    .unwrap_or(false)
            })
            .copied()
            .ok_or_else(|| Error::UnsupportedCurve("Unknown curve in key".to_string()))?;

        let private_key_bn = ec_key.private_key();
        let key_bytes = private_key_bn.to_vec();

        // Pad to expected size if necessary
        let mut padded_bytes = vec![0u8; curve.key_size()];
        let start_idx = curve.key_size().saturating_sub(key_bytes.len());
        padded_bytes[start_idx..].copy_from_slice(&key_bytes);

        Ok(Self {
            curve,
            key_data: SecureBytes::new(padded_bytes),
            openssl_key: pk,
        })
    }

    /// Get the curve used by this key
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.expose_secret()
    }

    /// Get the OpenSSL PKey
    pub fn as_openssl_pkey(&self) -> &PKey<Private> {
        &self.openssl_key
    }

    /// Derive the corresponding public key
    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        let ec_key = self.openssl_key.ec_key()?;
        let public_point = ec_key.public_key();
        let group = ec_key.group();

        // Get uncompressed point representation
        let mut ctx = BigNumContext::new()?;
        let point_bytes = public_point.to_bytes(group, Form::UNCOMPRESSED, &mut ctx)?;

        PublicKey::from_bytes(self.curve, &point_bytes)
    }

    /// Export key in PKCS#8 DER format
    pub fn to_pkcs8_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.openssl_key.private_key_to_der()?)
    }

    /// Export key in PKCS#8 PEM format
    pub fn to_pkcs8_pem(&self) -> CryptoResult<String> {
        let pem_bytes = self.openssl_key.private_key_to_pem_pkcs8()?;
        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("curve", &self.curve)
            .field("key_data", &"[REDACTED]")
            .finish()
    }
}

/// Represents a public key
#[derive(Clone, Debug)]
pub struct PublicKey {
    curve: Curve,
    point_data: Vec<u8>,
    openssl_key: PKey<Public>,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve && self.point_data == other.point_data
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    /// Create a public key from uncompressed point bytes
    pub fn from_bytes(curve: Curve, point_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let len = point_bytes.as_ref().len();
        if len != curve.uncompressed_point_size() && len != curve.coordinate_size() + 1 {
            return Err(Error::Invalid(format!(
                "Invalid point size: expected {} or {} bytes, got {len}",
                curve.uncompressed_point_size(),
                curve.coordinate_size() + 1
            )));
        }

        let group = curve.to_ec_group()?;
        let mut ctx = BigNumContext::new()?;

        let uncompressed = if point_bytes.as_ref()[0] == 0x04 {
            point_bytes.as_ref().to_vec()
        } else if point_bytes.as_ref()[0] == 0x02 || point_bytes.as_ref()[0] == 0x03 {
            // Convert to uncompressed format
            let point = EcPoint::from_bytes(&group, point_bytes.as_ref(), &mut ctx)?;
            let mut ctx = BigNumContext::new()?;
            point.to_bytes(&group, Form::UNCOMPRESSED, &mut ctx)?
        } else {
            return Err(Error::Invalid(format!(
                "Point must be in correct uncompressed or compressed format"
            )));
        };

        let point = EcPoint::from_bytes(&group, &uncompressed, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        Ok(Self {
            curve,
            point_data: uncompressed,
            openssl_key: pkey,
        })
    }

    /// Import key from SubjectPublicKeyInfo DER format
    pub fn from_der(der_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let pkey = PKey::public_key_from_der(der_bytes.as_ref())?;
        Self::pk_to_public(pkey)
    }

    pub fn from_pem(pem_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let pkey = PKey::public_key_from_pem(pem_bytes.as_ref())?;
        Self::pk_to_public(pkey)
    }

    fn pk_to_public(pkey: PKey<Public>) -> CryptoResult<Self> {
        let ec_key = pkey.ec_key()?;
        let group = ec_key.group();

        // Determine curve from the group
        let curve = Curve::all()
            .iter()
            .find(|&&c| {
                c.to_ec_group()
                    .map(|g| g.curve_name() == group.curve_name())
                    .unwrap_or(false)
            })
            .copied()
            .ok_or_else(|| Error::UnsupportedCurve("Unknown curve in key".to_string()))?;

        let point = ec_key.public_key();
        let mut ctx = BigNumContext::new()?;
        let point_bytes = point.to_bytes(group, Form::UNCOMPRESSED, &mut ctx)?;

        Ok(Self {
            curve,
            point_data: point_bytes,
            openssl_key: pkey,
        })
    }

    /// Create from hex string representation of point bytes
    pub fn from_hex(curve: Curve, hex_str: &str) -> CryptoResult<Self> {
        let point_bytes = hex::decode(hex_str)?;
        Self::from_bytes(curve, &point_bytes)
    }

    /// Get the curve used by this key
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// Get the uncompressed point bytes
    pub fn uncompressed_bytes(&self) -> &[u8] {
        &self.point_data
    }

    /// Get the compressed point bytes
    pub fn compressed_bytes(&self) -> CryptoResult<Vec<u8>> {
        let ec_key = self.openssl_key.ec_key()?;
        let point = ec_key.public_key();
        let group = ec_key.group();

        let mut ctx = BigNumContext::new()?;
        Ok(point.to_bytes(group, Form::COMPRESSED, &mut ctx)?)
    }

    /// Get the OpenSSL PKey of this public key
    pub fn as_openssl_pkey(&self) -> &PKey<Public> {
        &self.openssl_key
    }

    /// Get the X coordinate of the point
    pub fn x_coordinate(&self) -> CryptoResult<Vec<u8>> {
        let coord_size = self.curve.coordinate_size();
        if self.point_data.len() < 1 + coord_size {
            return Err(Error::Invalid("Point data is too short".to_string()));
        }
        Ok(self.point_data[1..1 + coord_size].to_vec())
    }

    /// Get the Y coordinate of the point
    pub fn y_coordinate(&self) -> CryptoResult<Vec<u8>> {
        let coord_size = self.curve.coordinate_size();
        if self.point_data.len() < 1 + 2 * coord_size {
            return Err(Error::Invalid("Point data is too short".to_string()));
        }
        Ok(self.point_data[1 + coord_size..1 + 2 * coord_size].to_vec())
    }

    /// Export key in SubjectPublicKeyInfo DER format
    pub fn to_der(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.openssl_key.public_key_to_der()?)
    }

    /// Export key in SubjectPublicKeyInfo PEM format
    pub fn to_pem(&self) -> CryptoResult<String> {
        let pem_bytes = self.openssl_key.public_key_to_pem()?;
        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }

    /// Convert point bytes to hex string representation
    pub fn to_hex(&self) -> String {
        hex::encode(&self.point_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_generation() {
        for &curve in Curve::all() {
            let private_key = PrivateKey::generate(curve).unwrap();
            assert_eq!(private_key.curve(), curve);
            assert_eq!(private_key.as_bytes().len(), curve.key_size());

            // Test public key derivation
            let public_key = private_key.public_key().unwrap();
            assert_eq!(public_key.curve(), curve);
        }
    }

    #[test]
    fn test_key_serialization() {
        let curve = Curve::NistP256;
        let private_key = PrivateKey::generate(curve).unwrap();
        let public_key = private_key.public_key().unwrap();

        // Test DER serialization
        let private_der = private_key.to_pkcs8_der().unwrap();
        let recovered_private = PrivateKey::from_pkcs8_der(&private_der).unwrap();
        assert_eq!(recovered_private.curve(), curve);

        let public_der = public_key.to_der().unwrap();
        let recovered_public = PublicKey::from_der(&public_der).unwrap();
        assert_eq!(recovered_public, public_key);

        // Test PEM serialization
        let private_pem = private_key.to_pkcs8_pem().unwrap();
        let recovered_private_pem = PrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(recovered_private_pem.curve(), curve);

        let public_pem = public_key.to_pem().unwrap();
        let recovered_public_pem = PublicKey::from_pem(&public_pem).unwrap();
        assert_eq!(recovered_public_pem, public_key);

        // Test hex serialization for public key
        let hex_str = public_key.to_hex();
        let recovered_from_hex = PublicKey::from_hex(curve, &hex_str).unwrap();
        assert_eq!(recovered_from_hex, public_key);
    }

    #[test]
    fn pem_serialization() {
        let curve = Curve::NistP256;
        let private_key = PrivateKey::generate(curve).unwrap();
        let private_pem = private_key.to_pkcs8_pem().unwrap().trim().to_string();
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_pem.ends_with("-----END PRIVATE KEY-----"));

        let public_key = private_key.public_key().unwrap();
        let public_pem = public_key.to_pem().unwrap().trim().to_string();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(public_pem.ends_with("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::new(&*data);
        assert_eq!(secure.len(), 5);
        assert_eq!(secure.expose_secret(), &data);

        let hex_str = secure.to_hex();
        let recovered = SecureBytes::from_hex(&hex_str).unwrap();
        assert_eq!(recovered.expose_secret(), secure.expose_secret());
    }

    #[test]
    fn test_point_formats() {
        let curve = Curve::NistP256;
        let private_key = PrivateKey::generate(curve).unwrap();
        let public_key = private_key.public_key().unwrap();

        // Test compressed format
        let compressed = public_key.compressed_bytes().unwrap();
        let recovered = PublicKey::from_bytes(curve, &compressed).unwrap();
        assert_eq!(recovered, public_key);

        // Test coordinate extraction
        let x_coord = public_key.x_coordinate().unwrap();
        let y_coord = public_key.y_coordinate().unwrap();
        assert_eq!(x_coord.len(), curve.coordinate_size());
        assert_eq!(y_coord.len(), curve.coordinate_size());
    }
}
