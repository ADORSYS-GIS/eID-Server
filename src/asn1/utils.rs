use crate::asn1::cvcert::{CertificateExtensions, TerminalSectorExt};
use crate::asn1::oid::{
    EID_TYPE_HW_KEYSTORE, EID_TYPE_SE_CERTIFIED, EID_TYPE_SE_ENDORSED, ID_CA_ECDH,
    ID_CA_ECDH_AES_CBC_CMAC_128, ID_CA_ECDH_AES_CBC_CMAC_192, ID_CA_ECDH_AES_CBC_CMAC_256,
    ID_PK_ECDH, ID_RI_ECDH, ID_RI_ECDH_SHA_256, ID_RI_ECDH_SHA_384, ID_RI_ECDH_SHA_512,
    ID_SECURITY_OBJECT, SHA256_OID, SHA384_OID, SHA512_OID, STD_DOMAINPARAMS,
};
use crate::asn1::security_info::{
    MobileEIDTypeInfo, ProtocolParams, RestrictedIdDomainParamInfo, RestrictedIdInfo,
};
use crate::crypto::{
    Curve, Error as CryptoError, PublicKey,
    ecdsa::{self, EcdsaSig},
    sym::Cipher,
};
use crate::pki::truststore::{TrustStore, TrustStoreError};
use crate::{
    asn1::security_info::{
        ChipAuthDomainParamInfo, ChipAuthPubKeyInfo, ChipAuthenticationInfo, EFCardSecurity,
        SecurityInfo, SecurityInfos,
    },
    crypto::HashAlg,
};
use bincode::{Decode, Encode};
use rasn::types::{ObjectIdentifier, OctetString, SetOf};
use rasn::{
    der::{decode as der_decode, encode as der_encode},
    types::Integer,
};
use rasn_cms::{AlgorithmIdentifier, CertificateChoices, SignedData, SignerIdentifier, SignerInfo};
use rasn_pkix::{Certificate, SubjectPublicKeyInfo};

type Result<T> = std::result::Result<T, Error>;

// Chip Authentication version 2
const CA_VERSION_2: u8 = 2;
// Mobile EID version 1
const MOBILE_EID_VERSION_1: u8 = 1;
// Restricted Identification version 1
const RESTRICTED_ID_VERSION: u8 = 1;

// Mapping of standardized domain parameter IDs to curves (TR-03110-3 Table 4)
const DOMAIN_PARAM_ID_TO_CURVE: &[(u8, Curve)] = &[
    (12, Curve::NistP256),
    (13, Curve::BrainpoolP256r1),
    (15, Curve::NistP384),
    (16, Curve::BrainpoolP384r1),
    (17, Curve::BrainpoolP512r1),
    (18, Curve::NistP521),
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ASN.1 decode error: {0}")]
    Decode(#[from] rasn::error::DecodeError),

    #[error("ASN.1 encode error: {0}")]
    Encode(#[from] rasn::error::EncodeError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("Invalid data: {0}")]
    Invalid(String),
}

/// Supported Chip Authentication Algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum ChipAuthAlg {
    EcdhAesCbcCmac128,
    EcdhAesCbcCmac192,
    EcdhAesCbcCmac256,
}

impl ChipAuthAlg {
    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        match oid {
            ID_CA_ECDH_AES_CBC_CMAC_128 => Some(ChipAuthAlg::EcdhAesCbcCmac128),
            ID_CA_ECDH_AES_CBC_CMAC_192 => Some(ChipAuthAlg::EcdhAesCbcCmac192),
            ID_CA_ECDH_AES_CBC_CMAC_256 => Some(ChipAuthAlg::EcdhAesCbcCmac256),
            _ => None,
        }
    }

    pub fn to_oid(&self) -> &'static [u32] {
        match self {
            ChipAuthAlg::EcdhAesCbcCmac128 => ID_CA_ECDH_AES_CBC_CMAC_128,
            ChipAuthAlg::EcdhAesCbcCmac192 => ID_CA_ECDH_AES_CBC_CMAC_192,
            ChipAuthAlg::EcdhAesCbcCmac256 => ID_CA_ECDH_AES_CBC_CMAC_256,
        }
    }

    pub fn to_cipher(&self) -> Cipher {
        use crate::crypto::sym::Cipher;
        match self {
            ChipAuthAlg::EcdhAesCbcCmac128 => Cipher::Aes128Cbc,
            ChipAuthAlg::EcdhAesCbcCmac192 => Cipher::Aes192Cbc,
            ChipAuthAlg::EcdhAesCbcCmac256 => Cipher::Aes256Cbc,
        }
    }
}

/// Mobile eID Type per TR-03110 Amendment Section 2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum MobileEIDType {
    SECertified,
    SEEndorsed,
    HWKeyStore,
}

impl MobileEIDType {
    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        match oid {
            EID_TYPE_SE_CERTIFIED => Some(MobileEIDType::SECertified),
            EID_TYPE_SE_ENDORSED => Some(MobileEIDType::SEEndorsed),
            EID_TYPE_HW_KEYSTORE => Some(MobileEIDType::HWKeyStore),
            _ => None,
        }
    }

    pub fn to_oid(&self) -> &'static [u32] {
        match self {
            MobileEIDType::SECertified => EID_TYPE_SE_CERTIFIED,
            MobileEIDType::SEEndorsed => EID_TYPE_SE_ENDORSED,
            MobileEIDType::HWKeyStore => EID_TYPE_HW_KEYSTORE,
        }
    }
}

/// Supported Restricted Identification Algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum RestrictedIdAlg {
    EcdhSha256,
    EcdhSha384,
    EcdhSha512,
}

impl RestrictedIdAlg {
    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        match oid {
            ID_RI_ECDH_SHA_256 => Some(RestrictedIdAlg::EcdhSha256),
            ID_RI_ECDH_SHA_384 => Some(RestrictedIdAlg::EcdhSha384),
            ID_RI_ECDH_SHA_512 => Some(RestrictedIdAlg::EcdhSha512),
            _ => None,
        }
    }

    pub fn to_oid(&self) -> &'static [u32] {
        match self {
            RestrictedIdAlg::EcdhSha256 => ID_RI_ECDH_SHA_256,
            RestrictedIdAlg::EcdhSha384 => ID_RI_ECDH_SHA_384,
            RestrictedIdAlg::EcdhSha512 => ID_RI_ECDH_SHA_512,
        }
    }
}

/// Extract Chip Authentication v2 informations from SecurityInfos
///
/// Returns an empty vector if no supported information is found
pub fn extract_chip_auth_info(
    data: impl AsRef<[u8]>,
) -> Result<Vec<(ChipAuthenticationInfo, ChipAuthAlg)>> {
    let security_infos = SecurityInfos::from_der(data.as_ref())?;

    let chip_auth_infos = security_infos
        .0
        .to_vec()
        .iter()
        .filter_map(|info| {
            ChipAuthAlg::from_oid(info.protocol.as_ref())
                .and_then(|alg| parse_chip_auth_info(info).map(|info| (info, alg)))
        })
        .collect();
    Ok(chip_auth_infos)
}

/// Finds Chip Authentication v2 Domain Parameter informations from SecurityInfos
///
/// Returns an empty vector if no supported information is found
pub fn find_chip_auth_domain_params(
    data: impl AsRef<[u8]>,
) -> Result<Vec<(ChipAuthDomainParamInfo, Curve)>> {
    let security_infos = SecurityInfos::from_der(data.as_ref())?;

    let results = security_infos
        .0
        .to_vec()
        .iter()
        .filter(|info| info.protocol.as_ref() == ID_CA_ECDH)
        .filter_map(|info| parse_domain_param_info(info))
        .collect();
    Ok(results)
}

/// Process EFCardSecurity to extract and validate chip's public key
///
/// This function:
/// 1. Parses the CMS SignedData structure
/// 2. Finds a trusted certificate from the trust store
/// 3. Verifies the signature on the SecurityInfos
/// 4. Extracts the chip's public key for the specified curve
///
/// # Errors
/// Returns an error if validation fails or required information is not found.
pub async fn process_card_security<T: TrustStore>(
    card_security: &EFCardSecurity,
    curve: Curve,
    trust_store: &T,
) -> Result<Vec<u8>> {
    let signed_data = &card_security.content;

    // Validate structure has required components
    validate_signed_data_structure(signed_data)?;

    // Find a trusted signer certificate and its corresponding SignerInfo
    let (signer_cert, signer_info) = find_trusted_signer(signed_data, trust_store).await?;

    // Validate the signature of the signed object
    verify_signature(signed_data, &signer_info, &signer_cert).await?;

    // Extract SecurityInfos from EncapsulatedContentInfo
    let content = signed_data.encap_content_info.content.as_ref().unwrap();
    let security_infos = SecurityInfos::from_der(content)?;

    // Extract and return the public point
    extract_chip_public_key(&security_infos, curve)
}

/// Parse Mobile eID information SecurityInfo from EFCardSecurity
pub fn parse_mobile_eid_info(
    card_security: &EFCardSecurity,
) -> Option<(MobileEIDTypeInfo, MobileEIDType)> {
    fn parse_mobile_eid(info: &SecurityInfo) -> Option<MobileEIDTypeInfo> {
        let version = der_decode::<Integer>(info.required_data.as_ref()).ok()?;
        if version != MOBILE_EID_VERSION_1.into() {
            return None;
        }
        Some(MobileEIDTypeInfo {
            protocol: info.protocol.clone(),
            version,
        })
    }

    let content = card_security.content.encap_content_info.content.as_ref()?;
    let security_infos = SecurityInfos::from_der(content).ok()?;
    security_infos
        .0
        .to_vec()
        .iter()
        .filter_map(|info| {
            MobileEIDType::from_oid(info.protocol.as_ref())
                .and_then(|alg| parse_mobile_eid(info).map(|info| (info, alg)))
        })
        .next()
}

/// Process restricted ID information from EFCardSecurity
///
/// This function:
/// 2. Finds a RestrictedIdDomainParamInfo with a supported curve
/// 3. Finds a supported authorized RestrictedIdInfo
/// 4. Returns the curve, corresponding RestrictedIdInfo, and RestrictedIdAlg
pub fn process_restricted_id(
    card_security: &EFCardSecurity,
) -> Option<(RestrictedIdInfo, RestrictedIdAlg, Curve)> {
    // Extract SecurityInfos from the encapsulated content
    let content = card_security.content.encap_content_info.content.as_ref()?;
    let security_infos = SecurityInfos::from_der(content).ok()?;

    // Find supported curve
    let curve = find_restricted_id_curve(&security_infos)?;
    // Find supported RestrictedIdInfo and corresponding algorithm
    let (restricted_id_info, alg) = extract_restricted_id_info(&security_infos)
        .ok()?
        .into_iter()
        .next()?;
    Some((restricted_id_info, alg, curve))
}

/// Parse Terminal Sector public key extension from CertificateExtensions
pub fn parse_terminal_sector(extensions: &CertificateExtensions) -> Option<TerminalSectorExt> {
    for ext in extensions.0.iter() {
        if let Ok(extension) = der_decode::<TerminalSectorExt>(ext.as_ref()) {
            return Some(extension);
        }
    }
    None
}

/// Parse ChipAuthenticationInfo from a SecurityInfo
fn parse_chip_auth_info(info: &SecurityInfo) -> Option<ChipAuthenticationInfo> {
    let version = der_decode::<Integer>(info.required_data.as_ref()).ok()?;

    // Only version 2 is currently supported
    if version != CA_VERSION_2.into() {
        return None;
    }
    let key_id = info
        .optional_data
        .as_ref()
        .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());

    Some(ChipAuthenticationInfo {
        protocol: info.protocol.clone(),
        version,
        key_id,
    })
}

/// Try to parse domain parameter info and curve from a SecurityInfo
fn parse_domain_param_info(info: &SecurityInfo) -> Option<(ChipAuthDomainParamInfo, Curve)> {
    let domain_parameter = der_decode::<AlgorithmIdentifier>(info.required_data.as_ref()).ok()?;
    // At least one standardized domain parameter must be present
    if domain_parameter.algorithm.as_ref() != STD_DOMAINPARAMS {
        return None;
    }

    let params = domain_parameter.parameters.as_ref()?;
    let curve_int = der_decode::<Integer>(params.as_ref()).ok()?;
    let curve_id: u8 = curve_int.try_into().ok()?;
    // Map curve id to curve
    let curve = DOMAIN_PARAM_ID_TO_CURVE
        .iter()
        .find(|(id, _)| *id == curve_id)
        .map(|(_, curve)| *curve)?;

    let key_id = info
        .optional_data
        .as_ref()
        .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());
    let info = ChipAuthDomainParamInfo {
        protocol: info.protocol.clone(),
        domain_parameter,
        key_id,
    };
    Some((info, curve))
}

/// Extract Restricted Identification informations from SecurityInfos
///
/// Returns an empty vector if no supported information is found
fn extract_restricted_id_info(
    info: &SecurityInfos,
) -> Result<Vec<(RestrictedIdInfo, RestrictedIdAlg)>> {
    Ok(info
        .0
        .to_vec()
        .iter()
        .filter_map(|info| {
            RestrictedIdAlg::from_oid(info.protocol.as_ref())
                .and_then(|alg| parse_restricted_id_info(info).map(|info| (info, alg)))
        })
        .collect())
}

/// Finds curve from RestrictedIdDomainParamInfo security info
fn find_restricted_id_curve(info: &SecurityInfos) -> Option<Curve> {
    info.0
        .to_vec()
        .iter()
        .filter(|info| info.protocol.as_ref() == ID_RI_ECDH)
        .filter_map(|info| parse_restricted_id_domain_param_info(info))
        .map(|(_, curve)| curve)
        .next()
}

/// Parse RestrictedIdentificationInfo from a SecurityInfo
fn parse_restricted_id_info(info: &SecurityInfo) -> Option<RestrictedIdInfo> {
    let params = der_decode::<ProtocolParams>(info.required_data.as_ref()).ok()?;
    if params.version != RESTRICTED_ID_VERSION.into() {
        return None;
    }
    let max_key_len = info
        .optional_data
        .as_ref()
        .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());

    Some(RestrictedIdInfo {
        protocol: info.protocol.clone(),
        params: ProtocolParams {
            version: params.version,
            key_id: params.key_id,
            authorized_only: params.authorized_only,
        },
        max_key_len,
    })
}

/// Parse RestrictedIdentificationDomainParamInfo from a SecurityInfo
fn parse_restricted_id_domain_param_info(
    info: &SecurityInfo,
) -> Option<(RestrictedIdDomainParamInfo, Curve)> {
    let domain_parameter = der_decode::<AlgorithmIdentifier>(info.required_data.as_ref()).ok()?;
    if domain_parameter.algorithm.as_ref() != STD_DOMAINPARAMS {
        return None;
    }

    let params = domain_parameter.parameters.as_ref()?;
    let curve_int = der_decode::<Integer>(params.as_ref()).ok()?;
    let curve_id: u8 = curve_int.try_into().ok()?;
    let curve = DOMAIN_PARAM_ID_TO_CURVE
        .iter()
        .find(|(id, _)| *id == curve_id)
        .map(|(_, curve)| *curve)?;

    let info = RestrictedIdDomainParamInfo {
        protocol: info.protocol.clone(),
        domain_parameter,
    };
    Some((info, curve))
}

/// Validate that SignedData has the required structure
fn validate_signed_data_structure(data: &SignedData) -> Result<()> {
    // Check for certificates
    if data.certificates.is_none() || data.certificates.as_ref().unwrap().is_empty() {
        return Err(Error::Invalid("No certificates found in SignedData".into()));
    }

    // Check for signer infos
    if data.signer_infos.is_empty() {
        return Err(Error::Invalid("No signer infos found in SignedData".into()));
    }

    // Check for encapsulated content
    if data.encap_content_info.content.is_none() {
        return Err(Error::Invalid("No encapsulated content found".into()));
    }
    Ok(())
}

/// Finds a trusted signer certificate and its corresponding SignerInfo
async fn find_trusted_signer<T: TrustStore>(
    signed_data: &SignedData,
    trust_store: &T,
) -> Result<(Certificate, SignerInfo)> {
    let certificates = signed_data.certificates.as_ref().unwrap();
    let signer_infos = &signed_data.signer_infos;

    // Try each certificate with each SignerInfo to find a trusted combination
    for cert_choice in certificates.to_vec() {
        let cert = match cert_choice {
            CertificateChoices::Certificate(c) => c.as_ref(),
            _ => continue,
        };

        // Check if this certificate is trusted
        let cert_der = der_encode(cert)?;
        if !trust_store.verify([cert_der]).await? {
            continue;
        }

        // Find matching SignerInfo for this certificate
        if let Some(signer_info) = find_matching_signer_info(signer_infos, cert) {
            return Ok((cert.clone(), signer_info.clone()));
        }
    }
    Err(Error::Invalid("No trusted certificate found".into()))
}

/// Find a SignerInfo that matches the given certificate
fn find_matching_signer_info<'a>(
    signer_infos: &'a SetOf<SignerInfo>,
    cert: &Certificate,
) -> Option<&'a SignerInfo> {
    // OID for Subject Key Identifier: 2.5.29.14
    const SKI_OID: &[u32] = &[2, 5, 29, 14];

    let signer_info_vec = signer_infos.to_vec();
    let result = signer_info_vec.iter().find(|info| match &info.sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
            issuer_and_serial.issuer == cert.tbs_certificate.issuer
                && issuer_and_serial.serial_number == cert.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(subject_key_id) => {
            // Extract SKI from certificate extensions and compare
            let extensions = cert.tbs_certificate.extensions.as_ref();
            extensions
                .map(|exts| {
                    exts.iter()
                        .find(|ext| ext.extn_id.as_ref() == SKI_OID)
                        .and_then(|ext| der_decode::<OctetString>(&ext.extn_value).ok())
                        .map(|ski| ski.as_ref() == subject_key_id.as_ref())
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        }
    });
    result.map(|v| &**v)
}

async fn verify_signature(
    signed_data: &SignedData,
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
) -> Result<()> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    // TR-03110-3 A.1.2.5: SignedAttributes must be present
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Invalid("Missing SignedAttributes in SignerInfo".into()))?;

    // compute the digest of the encapsulated content
    let content = signed_data.encap_content_info.content.as_ref().unwrap();
    let digest_alg = &signer_info.digest_algorithm;
    let (hash_alg, content_digest) = match digest_alg.algorithm.as_ref() {
        oid if oid == SHA256_OID => (HashAlg::Sha256, Sha256::digest(content).to_vec()),
        oid if oid == SHA384_OID => (HashAlg::Sha384, Sha384::digest(content).to_vec()),
        oid if oid == SHA512_OID => (HashAlg::Sha512, Sha512::digest(content).to_vec()),
        _ => return Err(Error::Invalid("Unsupported digest algorithm".into())),
    };

    // RFC 5652: the signature is over the DER encoding of SignedAttributes,
    let signed_attrs = get_signature_input(signed_attrs, &content_digest)?;

    // Get the public key from the signer certificate
    let pub_key_info = &signer_cert.tbs_certificate.subject_public_key_info;
    let pub_key_der = der_encode(pub_key_info)?;
    let public_key = PublicKey::from_der(&pub_key_der)?;

    // Verify the signature
    let signature = EcdsaSig::from_der(public_key.curve(), &signer_info.signature)?;
    if !ecdsa::verify(&public_key, &signed_attrs, &signature, hash_alg)? {
        return Err(Error::Invalid("Signature verification failed".into()));
    }
    Ok(())
}

/// Validate required attributes and get signature input
fn get_signature_input(
    signed_attrs: &SetOf<rasn_cms::Attribute>,
    expected_digest: &[u8],
) -> Result<Vec<u8>> {
    const CONTENT_TYPE_OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 3];
    const MESSAGE_DIGEST_OID: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];

    let mut found_content_type = false;
    let mut found_message_digest = false;

    for attr in signed_attrs.to_vec().iter() {
        match attr.r#type.as_ref() {
            CONTENT_TYPE_OID => {
                // Content-type should match eContentType
                if let Some(value) = attr.values.to_vec().first() {
                    let content_type_oid = der_decode::<ObjectIdentifier>(value.as_ref())?;
                    if content_type_oid.as_ref() != ID_SECURITY_OBJECT {
                        return Err(Error::Invalid(
                            "Content-type attribute and eContentType mismatch".into(),
                        ));
                    }
                    found_content_type = true;
                }
            }
            MESSAGE_DIGEST_OID => {
                if let Some(value) = attr.values.to_vec().first() {
                    let digest = der_decode::<OctetString>(value.as_ref())?;
                    if digest.as_ref() != expected_digest {
                        return Err(Error::Invalid(
                            "Message digest in signedAttrs does not match computed digest".into(),
                        ));
                    }
                    found_message_digest = true;
                }
            }
            _ => {}
        }
    }
    if found_content_type && found_message_digest {
        Ok(der_encode(signed_attrs)?)
    } else {
        Err(Error::Invalid(
            "Missing required attributes in SignedAttributes".into(),
        ))
    }
}

/// Extract chip's public key for the specified curve
fn extract_chip_public_key(security_infos: &SecurityInfos, curve: Curve) -> Result<Vec<u8>> {
    let domain_info = find_domain_param_info(security_infos, curve)?;
    let key_id = domain_info.key_id.clone();
    let pub_key_info = find_pubkey_info(security_infos, key_id, curve)?;

    // Extract the public point
    let mut subject_pub_key = pub_key_info.chip_auth_pubkey.subject_public_key;
    subject_pub_key.set_uninitialized(false);
    let bytes = subject_pub_key.into_vec();
    if bytes[0] != 0x04 {
        return Err(Error::Invalid(
            "Expected uncompressed point format (0x04)".into(),
        ));
    }
    Ok(bytes)
}

fn find_domain_param_info(
    security_infos: &SecurityInfos,
    target_curve: Curve,
) -> Result<ChipAuthDomainParamInfo> {
    security_infos
        .0
        .to_vec()
        .iter()
        .filter(|info| info.protocol.as_ref() == ID_CA_ECDH)
        .filter_map(|info| parse_domain_param_info(info))
        .find(|(_, curve)| *curve == target_curve)
        .ok_or_else(|| Error::Invalid(format!("No parameter found for curve {target_curve}")))
        .map(|(info, _)| info)
}

fn find_pubkey_info(
    security_infos: &SecurityInfos,
    key_id: Option<Integer>,
    curve: Curve,
) -> Result<ChipAuthPubKeyInfo> {
    for info in security_infos.0.to_vec() {
        if info.protocol.as_ref() != ID_PK_ECDH {
            continue;
        }

        let pubkey_info = der_decode::<SubjectPublicKeyInfo>(info.required_data.as_ref())?;
        let chip_auth_key_id = info
            .optional_data
            .as_ref()
            .and_then(|data| der_decode::<Integer>(data.as_ref()).ok());

        let chip_auth_info = ChipAuthPubKeyInfo {
            protocol: info.protocol.to_owned(),
            chip_auth_pubkey: pubkey_info,
            key_id: chip_auth_key_id,
        };

        if let Some(id) = &key_id {
            if chip_auth_info.key_id.as_ref() == Some(id) {
                return Ok(chip_auth_info);
            }
        } else if detect_curve_from_pubkey(&chip_auth_info) == Some(curve) {
            return Ok(chip_auth_info);
        }
    }
    Err(Error::Invalid(format!(
        "No public key info found for curve {curve}"
    )))
}

/// Detect curve from public key's AlgorithmIdentifier
fn detect_curve_from_pubkey(info: &ChipAuthPubKeyInfo) -> Option<Curve> {
    let alg_id = &info.chip_auth_pubkey.algorithm;
    if alg_id.algorithm.as_ref() != STD_DOMAINPARAMS {
        return None;
    }

    let params = alg_id.parameters.as_ref()?;
    let curve_int = der_decode::<Integer>(params.as_ref()).ok()?;
    let curve_id: u8 = curve_int.try_into().ok()?;
    DOMAIN_PARAM_ID_TO_CURVE
        .iter()
        .find(|(id, _)| *id == curve_id)
        .map(|(_, curve)| *curve)
}
