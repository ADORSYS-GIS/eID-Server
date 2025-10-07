use crate::asn1::{
    oid::{
        ID_CA_ECDH, ID_CA_ECDH_AES_CBC_CMAC_128, ID_CA_ECDH_AES_CBC_CMAC_192,
        ID_CA_ECDH_AES_CBC_CMAC_256, STD_DOMAINPARAMS,
    },
    security_info::{ChipAuthDomainParamInfo, ChipAuthenticationInfo, SecurityInfo, SecurityInfos},
};
use crate::crypto::Curve;
use rasn::{der::decode as der_decode, types::Integer};
use rasn_cms::AlgorithmIdentifier;

type Result<T> = std::result::Result<T, Error>;

// Supported Chip Authentication OIDs
const SUPPORTED_CHIP_AUTH_OIDS: &[&[u32]] = &[
    ID_CA_ECDH_AES_CBC_CMAC_128,
    ID_CA_ECDH_AES_CBC_CMAC_192,
    ID_CA_ECDH_AES_CBC_CMAC_256,
];

// Chip Authentication version 2
const CA_VERSION_2: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ASN.1 decode error: {0}")]
    Decode(#[from] rasn::error::DecodeError),

    #[error("ASN.1 encode error: {0}")]
    Encode(#[from] rasn::error::EncodeError),

    #[error("Invalid data: {0}")]
    Invalid(String),
}

/// Try to extract Chip Authentication v2 information from the SecurityInfos
///
/// Returns an empty vector if no supported Chip Authentication information is found
pub fn extract_chip_auth_info(hex: impl AsRef<str>) -> Result<Vec<ChipAuthenticationInfo>> {
    let security_infos = SecurityInfos::from_hex(hex)?;

    let chip_auth_infos = security_infos
        .0
        .to_vec()
        .iter()
        .filter(|info| SUPPORTED_CHIP_AUTH_OIDS.contains(&info.protocol.as_ref()))
        .filter_map(|info| try_parse_chip_auth_info(info))
        .collect();
    Ok(chip_auth_infos)
}

/// Try to parse a ChipAuthenticationInfo from a SecurityInfo
fn try_parse_chip_auth_info(security_info: &SecurityInfo) -> Option<ChipAuthenticationInfo> {
    let version = der_decode::<Integer>(security_info.required_data.as_ref()).ok()?;

    // Only version 2 is currently supported
    if version != CA_VERSION_2.into() {
        return None;
    }
    let key_id = security_info
        .optional_data
        .as_ref()
        .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());

    Some(ChipAuthenticationInfo {
        protocol: security_info.protocol.clone(),
        version,
        key_id,
    })
}

/// Try to find Chip Authentication v2 Domain Parameter information from the SecurityInfos
///
/// Returns an empty vector if no supported Chip Authentication Domain Parameter information is found
pub fn find_chip_auth_domain_param_info(
    hex: impl AsRef<str>,
) -> Result<Vec<(ChipAuthDomainParamInfo, Curve)>> {
    let security_infos = SecurityInfos::from_hex(hex)?;

    let results = security_infos
        .0
        .to_vec()
        .iter()
        .filter(|info| info.protocol.as_ref() == ID_CA_ECDH)
        .filter_map(|info| try_parse_domain_param_info(info))
        .collect();
    Ok(results)
}

/// Try to parse domain parameter info and curve from a SecurityInfo
fn try_parse_domain_param_info(
    security_info: &SecurityInfo,
) -> Option<(ChipAuthDomainParamInfo, Curve)> {
    let domain_parameter =
        der_decode::<AlgorithmIdentifier>(security_info.required_data.as_ref()).ok()?;
    // At least one standardized domain parameter must be present
    if domain_parameter.algorithm.as_ref() != STD_DOMAINPARAMS {
        return None;
    }

    let params = domain_parameter.parameters.as_ref()?;
    let curve_int = der_decode::<Integer>(params.as_ref()).ok()?;
    let curve_val: u8 = curve_int.try_into().ok()?;
    // Parse a curve from its integer identifier
    let curve = match curve_val {
        12 => Curve::NistP256,
        13 => Curve::BrainpoolP256r1,
        15 => Curve::NistP384,
        16 => Curve::BrainpoolP384r1,
        17 => Curve::BrainpoolP512r1,
        18 => Curve::NistP521,
        _ => return None,
    };

    let key_id = security_info
        .optional_data
        .as_ref()
        .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());
    let info = ChipAuthDomainParamInfo {
        protocol: security_info.protocol.clone(),
        domain_parameter,
        key_id,
    };
    Some((info, curve))
}
