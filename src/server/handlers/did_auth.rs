use crate::apdu::{ProtectedAPDU, SecureMessaging, SessionKeys, build_protected_cmds};
use crate::asn1::cvcert::Chat;
use crate::asn1::utils::{
    ChipAuthAlg, extract_chip_auth_info, find_chip_auth_domain_params, process_card_security,
};
use crate::crypto::ecdh::EcdhKeyPair;
use crate::crypto::{Curve, PublicKey};
use crate::crypto::{HashAlg, PrivateKey, ecdsa::EcdsaKeyPair};
use crate::cvcert::{AccessRights, CvCertificate};
use crate::domain::models::State;
use crate::domain::models::paos::{
    AuthProtoData, ConnectionHandle, DIDAuthenticate, DIDAuthenticateResponse, EAC1OutputType,
    EAC2InputType, EAC2OutputType, InputAPDUInfo, Transmit,
};
use crate::pki::identity::Material;
use crate::pki::truststore::TrustStore;
use crate::server::AppState;
use crate::server::errors::{AppError, PaosError, impl_paos_internal_error};
use crate::server::handlers::{SESSION_TRACKER, handle_paos_error};
use crate::session::SessionData;
use crate::soap::{Envelope, Header};
use serde::Serialize;
use validator::Validate;

const DID_NAME: &str = "PIN";
const EAC2_TYPE: &str = "EAC2InputType";
const EAC2_PROTOCOL_ID: &str = "urn:oid:1.3.162.15480.3.0.14.2";

#[derive(Debug, Serialize, Validate)]
struct DidAuthEac2 {
    #[validate(nested)]
    #[serde(rename = "DIDAuthenticate")]
    value: DIDAuthenticate<EAC2InputType>,
}

#[derive(Debug, Serialize)]
struct TransmitReq {
    #[serde(rename = "Transmit")]
    value: Transmit,
}

pub async fn handle_did_auth_eac1<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC1OutputType>>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, _, _) = get_ids(&envelope)?;

    match handle_eac1(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_paos_error(session_mgr, &session_id, e).await,
    }
}

pub async fn handle_did_auth_eac2<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC2OutputType>>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, _, _) = get_ids(&envelope)?;

    match handle_eac2(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_paos_error(session_mgr, &session_id, e).await,
    }
}

fn get_ids<T: Validate>(
    envelope: &Envelope<DIDAuthenticateResponse<T>>,
) -> Result<(String, String, String), AppError> {
    let mapped_id = envelope
        .header()
        .as_ref()
        .and_then(|h| h.relates_to.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());
    let session_id = SESSION_TRACKER
        .get(&mapped_id)
        .ok_or(PaosError::MissingPermissions)?;

    let relates_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());

    Ok((session_id, mapped_id, relates_to))
}

async fn handle_eac1<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC1OutputType>>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, mapped_session_id, relates_to) = get_ids(&envelope)?;

    let mut session_data: SessionData = session_mgr
        .get(&*session_id)
        .await
        .map_err(AppError::paos_internal)?
        .ok_or(PaosError::Timeout)?;

    let (conn_handle, aux_data, built_chat) = match &session_data.state {
        State::EAC1 {
            conn_handle,
            aux_data,
            built_chat,
        } => (conn_handle.clone(), aux_data.clone(), built_chat.clone()),
        _ => return Err(PaosError::Parameter("Expected state EAC1OutputType".into()).into()),
    };
    let body = envelope.into_body();

    // Validate request body
    let data = validate_eac1_body(body)?;

    let keypair_info = generate_eph_keypair(data.card_access.as_ref().unwrap())?;
    // Build DIDAuthenticate with EAC2InputType
    let resp = build_did_auth_eac2(state, aux_data, &keypair_info.0, &conn_handle, &data).await?;

    let message_id = uuid::Uuid::new_v4().urn().to_string();
    // Update the session tracker
    SESSION_TRACKER.invalidate(&mapped_session_id);
    SESSION_TRACKER.insert(message_id.clone(), session_id.clone());

    let header = Header {
        relates_to: Some(relates_to),
        message_id: Some(message_id),
    };

    let chat = &data.chat;
    let slot_handle = &conn_handle
        .slot_handle
        .ok_or_else(|| PaosError::Parameter("Missing slot handle".into()))?;
    let serialized_keypair = keypair_info.0.private_key().to_pkcs8_der()?;

    // Update session state
    session_data.state = State::EAC2 {
        slot_handle: slot_handle.into(),
        restricted_chat: chat.to_owned(),
        eph_key: serialized_keypair,
        chip_auth: (keypair_info.1, keypair_info.2),
        built_chat,
    };
    session_mgr.insert(session_id, &session_data).await?;

    resp.validate().map_err(AppError::paos_internal)?;
    let result = Envelope::new(resp).with_header(header).serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

async fn handle_eac2<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC2OutputType>>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, mapped_session_id, relates_to) = get_ids(&envelope)?;

    let mut session_data: SessionData = session_mgr
        .get(&*session_id)
        .await
        .map_err(AppError::paos_internal)?
        .ok_or(PaosError::Timeout)?;

    let State::EAC2 {
        slot_handle,
        restricted_chat,
        eph_key,
        chip_auth,
        built_chat,
    } = &session_data.state
    else {
        return Err(PaosError::Parameter("Expected state EAC2OutputType".into()).into());
    };
    let body = envelope.into_body();

    // Validate request body
    let data = validate_eac2_body(body)?;

    let access_rights = build_access_rights(restricted_chat, built_chat)?;
    let trust_store = &state.service.trust_store;
    let (cmds, session_keys) = build_cmds(&data, eph_key, chip_auth, trust_store, &access_rights).await?;

    // Build Transmit response
    let resp = build_transmit(slot_handle.clone(), &cmds).await?;

    let message_id = uuid::Uuid::new_v4().urn().to_string();
    // Update the session tracker
    SESSION_TRACKER.invalidate(&mapped_session_id);
    SESSION_TRACKER.insert(message_id.clone(), session_id.clone());

    let header = Header {
        relates_to: Some(relates_to),
        message_id: Some(message_id),
    };

    // Update session state with secure keys for response processing
    let cmds_len = cmds.len();
    
    // Create secure messaging keys from the session keys used to build commands
    let secure_keys = Some(crate::domain::models::SecureMessagingKeys::new(
        session_keys.k_enc.expose_secret().to_vec(),
        session_keys.k_mac.expose_secret().to_vec(),
        session_keys.cipher(),
        0, // Initial SSC starts at 0
    ));
    
    session_data.state = State::Transmit {
        apdu_cmds: cmds,
        cmds_len,
        secure_keys,
    };
    session_mgr.insert(session_id, &session_data).await?;

    let result = Envelope::new(resp).with_header(header).serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

fn validate_eac1_body(
    body: DIDAuthenticateResponse<EAC1OutputType>,
) -> Result<EAC1OutputType, AppError> {
    // Validate request body
    body.validate().map_err(PaosError::from)?;

    // Check for client errors
    if body.result.is_error() {
        return Err(AppError::paos_internal(PaosError::Parameter(format!(
            "Client respond with error: {:?}\nAborting session",
            body.result
        ))));
    }

    let data = body.data();
    if data.car.is_some() {
        return Err(AppError::Paos(PaosError::Parameter(
            "CertificateHolderAuthorizationTemplate should not be present at this stage".into(),
        )));
    }

    // Validate presence of required data
    if data.card_access.is_none() || data.challenge.is_none() || data.id_picc.is_none() {
        return Err(AppError::paos_internal(PaosError::Parameter(
            "Missing EAC1OutputType required fields in AuthenticationProtocolData".into(),
        )));
    }
    Ok(data)
}

fn validate_eac2_body(
    body: DIDAuthenticateResponse<EAC2OutputType>,
) -> Result<EAC2OutputType, AppError> {
    // Validate request body
    body.validate().map_err(PaosError::from)?;

    // Check for client errors
    if body.result.is_error() {
        return Err(AppError::paos_internal(PaosError::Parameter(format!(
            "Client respond with error: {:?}\nAborting session",
            body.result
        ))));
    }

    let data = body.data();
    if data.challenge.is_some() {
        return Err(AppError::Paos(PaosError::Parameter(
            "Challenge should not be present at this stage".into(),
        )));
    }

    // Validate presence of required data
    if data.card_security.is_none() || data.auth_token.is_none() || data.nonce.is_none() {
        return Err(AppError::paos_internal(PaosError::Parameter(
            "Missing EAC2OutputType required fields in AuthenticationProtocolData".into(),
        )));
    }
    Ok(data)
}

async fn build_did_auth_eac2<T: TrustStore>(
    state: &AppState<T>,
    aux_data: Option<String>,
    ecdh_keypair: &EcdhKeyPair,
    conn_handle: &ConnectionHandle,
    data: &EAC1OutputType,
) -> Result<DidAuthEac2, AppError> {
    let pub_point = ecdh_keypair.public_key().to_hex();
    let signature = generate_signature(aux_data, ecdh_keypair, state, data).await?;

    let eac2_input_type = EAC2InputType {
        protocol: EAC2_PROTOCOL_ID.into(),
        type_: Some(EAC2_TYPE.into()),
        certificates: None,
        eph_pubkey: pub_point,
        signature,
    };

    Ok(DidAuthEac2 {
        value: DIDAuthenticate {
            connection_handle: conn_handle.to_owned(),
            did_scope: None,
            did_name: DID_NAME.into(),
            auth_protocol_data: AuthProtoData {
                data: eac2_input_type,
            },
        },
    })
}

async fn generate_signature<T: TrustStore>(
    aux_data: Option<String>,
    ecdh_keypair: &EcdhKeyPair,
    state: &AppState<T>,
    data: &EAC1OutputType,
) -> Result<String, AppError> {
    let (keypair, hash_alg) = get_signature_params(state).await?;

    let mut tbs_data = vec![];
    tbs_data.extend_from_slice(&hex::decode(data.id_picc.as_ref().unwrap())?);
    tbs_data.extend_from_slice(&hex::decode(data.challenge.as_ref().unwrap())?);
    tbs_data.extend_from_slice(&ecdh_keypair.public_key().x_coordinate());
    if let Some(aux_data) = aux_data {
        tbs_data.extend_from_slice(&hex::decode(&aux_data)?);
    }

    let signature = keypair.sign(&tbs_data, hash_alg)?;
    Ok(signature.raw_to_hex()?)
}

async fn get_signature_params<T: TrustStore>(
    state: &AppState<T>,
) -> Result<(EcdsaKeyPair, HashAlg), AppError> {
    let identity = &state.service.identity;
    let (key_bytes, term_cvc_bytes) = tokio::try_join!(
        identity.get(Material::CvcKey),
        identity.get(Material::TermCvc),
    )?;

    let priv_key = PrivateKey::from_bytes(&key_bytes)?;
    let keypair = EcdsaKeyPair::from_private_key(priv_key)?;

    let term_cvc = CvCertificate::from_der(&term_cvc_bytes)?;
    let security_protocol = term_cvc.public_key().security_protocol();
    // safe to unwrap, because we will always generate
    // a key pair with a valid security protocol
    let hash_alg = security_protocol.unwrap().hash_algorithm();
    Ok((keypair, hash_alg))
}

fn generate_eph_keypair(card_access: &str) -> Result<(EcdhKeyPair, Curve, ChipAuthAlg), AppError> {
    let chip_auth_infos = extract_chip_auth_info(hex::decode(card_access)?)?;
    let chip_auth_params = find_chip_auth_domain_params(hex::decode(card_access)?)?;

    // Find a compatible chip auth parameters by matching key_ids
    let compatible_params = chip_auth_params.iter().find_map(|(param, curve)| {
        chip_auth_infos
            .iter()
            .find(|(info, _)| info.key_id == param.key_id)
            .map(|(_, chip_auth_alg)| (param, curve, chip_auth_alg))
    });

    if let Some((_, curve, chip_auth_alg)) = compatible_params {
        let ecdh_keypair = EcdhKeyPair::generate_ephemeral(*curve)?;
        Ok((ecdh_keypair, *curve, *chip_auth_alg))
    } else {
        Err(AppError::Paos(PaosError::Parameter(
            "No compatible domain parameter found".into(),
        )))
    }
}

async fn build_transmit(
    slot_handle: String,
    cmds: &[ProtectedAPDU],
) -> Result<TransmitReq, AppError> {
    let apdu_infos = cmds
        .iter()
        .map(|cmd| {
            let bytes = cmd.cmd.to_bytes();
            InputAPDUInfo {
                input_apdu: hex::encode_upper(bytes),
                accept_statuses: None,
            }
        })
        .collect();

    Ok(TransmitReq {
        value: Transmit {
            slot_handle,
            input_apdus: apdu_infos,
        },
    })
}

async fn build_cmds<T: TrustStore>(
    data: &EAC2OutputType,
    eph_key: &[u8],
    auth_params: &(Curve, ChipAuthAlg),
    trust_store: &T,
    access_rights: &AccessRights,
) -> Result<(Vec<ProtectedAPDU>, crate::apdu::SessionKeys), AppError> {
    let (curve, alg) = *auth_params;
    // process card security and extract public key
    let card_security = hex::decode(data.card_security.as_ref().unwrap())?;
    let pub_bytes = process_card_security(&card_security, curve, trust_store).await?;
    let card_pubkey = PublicKey::from_bytes(curve, pub_bytes)?;
    // get ephemeral private key from serialized DER key bytes
    let eph_priv_key = PrivateKey::from_bytes(eph_key)?;
    // Initialize secure messaging
    let nonce = hex::decode(data.nonce.as_ref().unwrap())?;
    let session_keys = SessionKeys::derive(&eph_priv_key, &card_pubkey, alg, nonce)?;
    let mut sm = SecureMessaging::new(session_keys.clone());

    // Validate authentication token
    validate_auth_token(&sm, &eph_priv_key, data.auth_token.as_ref().unwrap(), alg)?;

    // Use the APDU builder to construct commands
    let commands = build_protected_cmds(access_rights, &mut sm).map_err(AppError::from)?;
    Ok((commands, session_keys))
}

fn build_access_rights(
    restricted_chat: &Option<String>,
    built_chat: &(Option<String>, Option<String>),
) -> Result<AccessRights, AppError> {
    // If CHAT has been restricted, build on it
    if let Some(restricted_chat_hex) = restricted_chat {
        let chat = Chat::from_hex(restricted_chat_hex)?;
        return Ok(chat.access_rights());
    }

    // Otherwise build based on early built required and optional CHAT
    let (required_chat_hex, optional_chat_hex) = built_chat;
    let mut access_rights = AccessRights::new();

    // Parse required chat if present
    if let Some(required_hex) = required_chat_hex {
        let required_chat = Chat::from_hex(required_hex)?;
        for right in required_chat.access_rights().rights() {
            access_rights.add(*right);
        }
    }
    // Parse optional chat if present
    if let Some(optional_hex) = optional_chat_hex {
        let optional_chat = Chat::from_hex(optional_hex)?;
        for right in optional_chat.access_rights().rights() {
            access_rights.add(*right);
        }
    }
    Ok(access_rights)
}

fn validate_auth_token(
    sm: &SecureMessaging,
    ecdh_key: &PrivateKey,
    auth_token: &str,
    alg: ChipAuthAlg,
) -> Result<(), AppError> {
    use rasn::prelude::{ObjectIdentifier as Oid, *};

    #[derive(Debug, Clone, Decode, Encode, AsnType)]
    #[rasn(tag(application, 0x49))]
    struct PublicKey {
        pub oid: Oid,
        #[rasn(tag(context, 6))]
        pub public_point: OctetString,
    }

    let key = PublicKey {
        oid: Oid::new_unchecked(alg.to_oid().into()),
        public_point: ecdh_key.public_key()?.uncompressed_bytes().into(),
    };
    let der_key = rasn::der::encode(&key)?;

    let received_auth_token = hex::decode(auth_token)?;
    let computed_auth_token = sm.calculate_mac(der_key)?;
    if received_auth_token != computed_auth_token {
        return Err(PaosError::Parameter("Authentication token mismatch".into()).into());
    }
    Ok(())
}

impl_paos_internal_error! {
    crate::crypto::Error,
    crate::cvcert::Error,
}

impl From<hex::FromHexError> for AppError {
    fn from(error: hex::FromHexError) -> Self {
        AppError::Paos(PaosError::Parameter(error.to_string()))
    }
}

impl From<crate::asn1::utils::Error> for AppError {
    fn from(error: crate::asn1::utils::Error) -> Self {
        use crate::asn1::utils::Error;

        match error {
            Error::TrustStore(e) => AppError::paos_internal(e),
            _ => AppError::Paos(PaosError::Parameter(error.to_string())),
        }
    }
}

impl From<crate::apdu::Error> for AppError {
    fn from(error: crate::apdu::Error) -> Self {
        use crate::apdu::Error;
        match error {
            Error::Asn1(e) => AppError::paos_internal(e),
            _ => AppError::Paos(PaosError::Parameter(error.to_string())),
        }
    }
}
