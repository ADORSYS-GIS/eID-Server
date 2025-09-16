use crate::crypto::curves::Curve;
use crate::crypto::errors::{CryptoResult, Error};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm as Form};
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

impl From<&[u8]> for SecureBytes {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecureBytes {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<String> for SecureBytes {
    fn from(value: String) -> Self {
        Self::new(value.as_bytes())
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
        let group: EcGroup = curve.try_into()?;
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

    /// Create a new private key from DER encoded bytes
    pub fn from_bytes(key_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        Self::from_pkcs8_der(key_bytes)
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
        let curve: Curve = group.try_into()?;

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
        Ok(self.openssl_key.private_key_to_pkcs8()?)
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
    /// Create a public key from point bytes (uncompressed or compressed format)
    pub fn from_bytes(curve: Curve, point_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let len = point_bytes.as_ref().len();
        if len != curve.uncompressed_point_size() && len != curve.coordinate_size() + 1 {
            return Err(Error::Invalid(format!(
                "Invalid point size: expected {} or {} bytes, got {len}",
                curve.uncompressed_point_size(),
                curve.coordinate_size() + 1
            )));
        }

        let group: EcGroup = curve.try_into()?;
        let mut ctx = BigNumContext::new()?;

        let uncompressed = if point_bytes.as_ref()[0] == 0x04 {
            point_bytes.as_ref().to_vec()
        } else if point_bytes.as_ref()[0] == 0x02 || point_bytes.as_ref()[0] == 0x03 {
            // Convert to uncompressed format
            let point = EcPoint::from_bytes(&group, point_bytes.as_ref(), &mut ctx)?;
            let mut ctx = BigNumContext::new()?;
            point.to_bytes(&group, Form::UNCOMPRESSED, &mut ctx)?
        } else {
            return Err(Error::Invalid(
                "Point must be in correct uncompressed or compressed format".to_string(),
            ));
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

    /// Import key from SubjectPublicKeyInfo PEM format
    pub fn from_pem(pem_bytes: impl AsRef<[u8]>) -> CryptoResult<Self> {
        let pkey = PKey::public_key_from_pem(pem_bytes.as_ref())?;
        Self::pk_to_public(pkey)
    }

    fn pk_to_public(pkey: PKey<Public>) -> CryptoResult<Self> {
        let ec_key = pkey.ec_key()?;
        let group = ec_key.group();

        // Determine curve from the group
        let curve: Curve = group.try_into()?;

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
    pub fn x_coordinate(&self) -> Vec<u8> {
        // This is safe because the point data is always in uncompressed format
        self.point_data[1..1 + self.curve.coordinate_size()].to_vec()
    }

    /// Get the Y coordinate of the point
    pub fn y_coordinate(&self) -> Vec<u8> {
        // This is safe because the point data is always in uncompressed format
        let coord_size = self.curve.coordinate_size();
        self.point_data[1 + coord_size..1 + 2 * coord_size].to_vec()
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
    use hex_literal::hex;

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
        assert_eq!(recovered_private.as_bytes(), private_key.as_bytes());

        let public_der = public_key.to_der().unwrap();
        let recovered_public = PublicKey::from_der(&public_der).unwrap();
        assert_eq!(recovered_public, public_key);

        // Test PEM serialization
        let private_pem = private_key.to_pkcs8_pem().unwrap();
        let recovered_private_pem = PrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(recovered_private_pem.curve(), curve);
        assert_eq!(recovered_private_pem.as_bytes(), private_key.as_bytes());

        let public_pem = public_key.to_pem().unwrap();
        let recovered_public_pem = PublicKey::from_pem(&public_pem).unwrap();
        assert_eq!(recovered_public_pem, public_key);

        // Test hex serialization for public key
        let hex_str = public_key.to_hex();
        let recovered_from_hex = PublicKey::from_hex(curve, &hex_str).unwrap();
        assert_eq!(recovered_from_hex, public_key);
    }

    #[test]
    fn priv_pem_serialization() {
        let original_pem = include_str!("../../test_data/ec_keys/brainpoolp256r1.pem");

        let result = PrivateKey::from_pkcs8_pem(original_pem);
        assert!(result.is_ok());
        let private_key = result.unwrap();
        assert!(private_key.curve() == Curve::BrainpoolP256r1);
        assert_eq!(
            private_key.as_bytes().len(),
            Curve::BrainpoolP256r1.key_size()
        );

        let serialized = private_key.to_pkcs8_pem();
        assert!(serialized.is_ok());
        let serialized = serialized.unwrap();
        assert_eq!(serialized, original_pem);
    }

    #[test]
    fn private_key_der_serialization() {
        let original_der = include_bytes!("../../test_data/ec_keys/brainpoolp256r1.der");

        let result = PrivateKey::from_pkcs8_der(original_der);
        assert!(result.is_ok());
        let private_key = result.unwrap();
        assert!(private_key.curve() == Curve::BrainpoolP256r1);
        assert_eq!(
            private_key.as_bytes().len(),
            Curve::BrainpoolP256r1.key_size()
        );

        let serialized = private_key.to_pkcs8_der();
        assert!(serialized.is_ok());
        let serialized = serialized.unwrap();
        assert_eq!(serialized, original_der);
    }

    #[test]
    fn test_public_key_serialization() {
        let brainpoolp256_der = hex!(
            "308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D01"
            "01022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D"
            "1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6C"
            "E94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7"
            "E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27"
            "E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745"
            "132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D71"
            "8C397AA3B561A6F7901E0E82974856A7020101034200049F6E760D63B67A3059"
            "1172DB8662C52EAFEA4B26EF7CD3EFA68B310680847D1D2816930F1FD28D9BF9"
            "F8803DD7DD0C4DFBB93D9D2B152DB24ACB22D37908F521"
        );
        let expected_uncompressed = hex!(
            "04"
            "9F6E760D63B67A30591172DB8662C52EAFEA4B26EF7CD3EFA68B310680847D1D"
            "2816930F1FD28D9BF9F8803DD7DD0C4DFBB93D9D2B152DB24ACB22D37908F521"
        );

        let result = PublicKey::from_der(brainpoolp256_der);
        assert!(result.is_ok());
        let public_key = result.unwrap();
        assert_eq!(public_key.curve(), Curve::BrainpoolP256r1);
        assert_eq!(public_key.uncompressed_bytes(), expected_uncompressed);

        let serialized = public_key.to_der();
        assert!(serialized.is_ok());
        let serialized = serialized.unwrap();
        assert_eq!(serialized, brainpoolp256_der);
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
        let x_coord = public_key.x_coordinate();
        let y_coord = public_key.y_coordinate();
        assert_eq!(x_coord.len(), curve.coordinate_size());
        assert_eq!(y_coord.len(), curve.coordinate_size());
    }

    #[test]
    fn test_public_key_components() {
        let curve = Curve::BrainpoolP256r1;
        let key_bytes = hex!(
            "04"
            "19d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f"
            "17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f8"
        );
        let expected_x = hex!("19d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f");
        let expected_y = hex!("17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f8");
        let expected_compressed =
            hex!("02 19d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f");

        let public_key = PublicKey::from_bytes(curve, key_bytes).unwrap();
        let compressed = public_key.compressed_bytes().unwrap();

        assert_eq!(public_key.curve(), curve);
        assert_eq!(public_key.x_coordinate(), expected_x);
        assert_eq!(public_key.y_coordinate(), expected_y);
        assert!(compressed == expected_compressed);
    }

    #[test]
    fn test_public_key_validation() {
        let nist_p256 = Curve::NistP256;
        let private_key = PrivateKey::generate(nist_p256).unwrap();
        let public_key = private_key.public_key();
        assert!(public_key.is_ok());

        let nist_p256_bytes = hex!(
            "04"
            "73039e0c42c496afb3f287ca7ef6b90bea2ab166696fb57b12b1bde7a7434fd6"
            "b41c9550b5a58040784d87816cda1c9d485edeab4c6931f947323554db382a5c"
        );
        let public_key = PublicKey::from_bytes(nist_p256, nist_p256_bytes);
        assert!(public_key.is_ok());

        let brainpool_p256r1_bytes = hex!(
            "04"
            "19d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f"
            "17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f8"
        );
        let public_key = PublicKey::from_bytes(nist_p256, brainpool_p256r1_bytes);
        assert!(public_key.is_err());
    }

    #[test]
    fn test_invalid_public_key() {
        let nist_p256_bytes = hex!(
            "04"
            "73039e0c42c496afb3f287ca7ef6b90bea2ab166696fb57b12b1bde7a7434fd6"
            "b41c9550b5a58040784d87816cda1c9d485edeab4c6931f947323554db382a5c"
        );
        // Should fail because the curve is wrong
        let brainpool_p256r1 = Curve::BrainpoolP256r1;
        let public_key = PublicKey::from_bytes(brainpool_p256r1, nist_p256_bytes);
        assert!(public_key.is_err());

        // BrainpoolP256r1 public key
        let brainpool_p256r1_bytes = hex!(
            "04"
            "19d4b7447788b0e1993db35500999627e739a4e5e35f02d8fb07d6122e76567f"
            "17758d7a3aa6943ef23e5e2909b3e8b31bfaa4544c2cbf1fb487f31ff239c8f8"
        );
        // Should fail because the curve is wrong
        let nist_p256 = Curve::NistP256;
        let result = PublicKey::from_bytes(nist_p256, brainpool_p256r1_bytes);
        assert!(result.is_err());
    }
}
