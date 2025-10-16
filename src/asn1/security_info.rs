use crate::asn1::oid::{ID_SECURITY_OBJECT, ID_SIGNED_DATA};
use rasn::error::DecodeError;
use rasn::prelude::{ObjectIdentifier as Oid, *};
use rasn::{Codec, error::DecodeErrorKind};
use rasn_cms::{AlgorithmIdentifier, ContentType, SignedData};
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
                msg: format!("Hex decode error: {e}"),
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

/// EF.CardSecurity is ContentInfo with contentType id-signedData
/// and the SignedData has eContentType id-SecurityObject
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct EFCardSecurity {
    pub content_type: ContentType,
    #[rasn(tag(explicit(0)))]
    pub content: SignedData,
}

impl EFCardSecurity {
    /// Decode the EF.CardSecurity from DER encoded data
    pub fn from_der(der: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        let value = rasn::der::decode::<Self>(der.as_ref())?;

        // Validate content type is id-signedData
        if value.content_type.as_ref() != ID_SIGNED_DATA {
            return Err(DecodeError::from_kind(
                DecodeErrorKind::Custom {
                    msg: "Invalid content type, expected id-signedData".into(),
                },
                Codec::Der,
            ));
        }
        // Validate encapsulated content type is id-securityObject
        let encap_content_type = &value.content.encap_content_info.content_type;
        if encap_content_type.as_ref() != ID_SECURITY_OBJECT {
            return Err(DecodeError::from_kind(
                DecodeErrorKind::Custom {
                    msg: "Invalid content type, expected id-securityObject".into(),
                },
                Codec::Der,
            ));
        }
        Ok(value)
    }

    /// Decode the EF.CardSecurity from hex representation of DER encoded data
    pub fn from_hex(hex: impl AsRef<str>) -> Result<Self, DecodeError> {
        let der = decode_hex(hex.as_ref())?;
        Self::from_der(&der)
    }
}

/// Security mechanism used by the mobile electronic identity
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsnType, Encode, Decode)]
pub struct MobileEIDTypeInfo {
    /// (d-mobileEIDType-SECertified | id-mobileEIDType-SEEndorsed | id-mobileEIDType-HWKeyStore)
    pub protocol: Oid,
    /// Version -- should be 1
    pub version: Integer,
}
