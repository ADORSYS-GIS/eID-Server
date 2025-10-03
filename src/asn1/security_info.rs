use rasn::error::DecodeError;
use rasn::prelude::{ObjectIdentifier as Oid, *};
use rasn::{Codec, error::DecodeErrorKind};
use rasn_cms::AlgorithmIdentifier;
use rasn_pkix::SubjectPublicKeyInfo;

/// EF.CardAccess is SecurityInfos defined in TR 3110 Part 3
pub type EFCardAccess = SecurityInfos;

/// SecurityInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER,
///     requiredData ANY DEFINED BY protocol,
///     optionalData ANY DEFINED BY protocol OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct SecurityInfo {
    pub protocol: Oid,
    pub required_data: Any,
    pub optional_data: Option<Any>,
}

/// SecurityInfos ::= SET OF SecurityInfo
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Encode, Decode)]
#[rasn(delegate)]
pub struct SecurityInfos(pub SetOf<SecurityInfo>);

impl SecurityInfos {
    /// Decode the SecurityInfos from DER encoded data
    pub fn from_der(der: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        rasn::der::decode(der.as_ref())
    }

    /// Decode the SecurityInfos from hex representation of DER encoded data
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self, DecodeError> {
        let der = decode_hex(hex.as_ref())?;
        Self::from_der(&der)
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, DecodeError> {
    hex::decode(hex).map_err(|e| {
        DecodeError::from_kind(
            DecodeErrorKind::Custom {
                msg: format!("Hex decode error: {e}").into(),
            },
            Codec::Der,
        )
    })
}

/// Chip Authentication Info
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct ChipAuthenticationInfo {
    /// Protocol OID
    pub protocol: Oid,
    /// Version: 1, 2, or 3
    pub version: Integer,
    /// used to indicate the local key identifier
    #[rasn(default)]
    pub key_id: Option<Integer>,
}

/// Chip Authentication Domain Parameter Info
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct ChipAuthDomainParamInfo {
    /// Protocol OID (id-CA-DH | id-CA-ECDH)
    pub protocol: Oid,
    /// Domain parameters
    pub domain_parameter: AlgorithmIdentifier,
    /// used to indicate the local key identifier
    #[rasn(default)]
    pub key_id: Option<Integer>,
}

/// Chip Authentication Public Key Info
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct ChipAuthPubKeyInfo {
    /// Protocol OID (id-PK-DH | id-PK-ECDH)
    pub protocol: Oid,
    /// Encoded public key
    pub chip_auth_pubkey: SubjectPublicKeyInfo,
    /// used to indicate the local key identifier
    #[rasn(default)]
    pub key_id: Option<Integer>,
}

/// Standardized Domain Parameter Algorithm Identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct StdDomainParamAlgIdentifier {
    pub algorithm: Oid,
    pub std_domain_param: Integer,
}
