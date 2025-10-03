use crate::asn1::utils::{extract_chip_auth_info, find_chip_auth_domain_param_info};
use crate::crypto::ecdh::EcdhKeyPair;
use crate::crypto::{HashAlg, PrivateKey, ecdsa::EcdsaKeyPair};
use crate::cvcert::CvCertificate;
use crate::domain::models::State;
use crate::domain::models::paos::{
    AuthProtoData, ConnectionHandle, DIDAuthenticate, DIDAuthenticateResponse, EAC1OutputType,
    EAC2InputType, StartPaosResponse,
};
use crate::pki::identity::Material;
use crate::pki::truststore::TrustStore;
use crate::server::AppState;
use crate::server::errors::{AppError, PaosError, impl_paos_internal_error};
use crate::server::handlers::SESSION_TRACKER;
use crate::session::{SessionData, SessionManager};
use crate::soap::{Envelope, Header};
use serde::Serialize;
use validator::Validate;

const DID_NAME: &str = "PIN";
const EAC2_TYPE: &str = "EAC2InputType";
const EAC2_PROTOCOL_ID: &str = "urn:oid:1.3.162.15480.3.0.14.2";

#[derive(Debug, Serialize)]
struct StartPaosResp {
    #[serde(rename = "StartPAOSResponse")]
    resp: StartPaosResponse,
}

#[derive(Debug, Serialize, Validate)]
struct DidAuthEac2 {
    #[validate(nested)]
    #[serde(rename = "DIDAuthenticate")]
    value: DIDAuthenticate<EAC2InputType>,
}

impl StartPaosResp {
    pub fn error<T: Into<AppError>>(error: T) -> Self {
        Self {
            resp: StartPaosResponse {
                result: error.into().to_result(),
            },
        }
    }
}

async fn handle_error<E: Into<AppError>>(
    session_mgr: &SessionManager,
    session_id: Option<&str>,
    error: E,
) -> Result<String, AppError> {
    if let Some(session_id) = session_id {
        if let Err(e) = session_mgr.remove(session_id).await {
            tracing::warn!("Failed to remove session {session_id}: {e:?}");
        }
    }
    let env = Envelope::new(StartPaosResp::error(error));
    env.serialize_paos(true).map_err(AppError::paos_internal)
}

pub async fn handle_did_authenticate<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC1OutputType>>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;

    match handle_inner(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_error(session_mgr, None, e).await,
    }
}

async fn handle_inner<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<DIDAuthenticateResponse<EAC1OutputType>>,
) -> Result<String, AppError> {
    let id_map = envelope
        .header()
        .as_ref()
        .and_then(|h| h.relates_to.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());
    let session_id = SESSION_TRACKER
        .get(&id_map)
        .ok_or(PaosError::MissingPermissions)?;
    let relates_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());
    let session_mgr = &state.service.session_manager;
    let mut session_data: SessionData = session_mgr
        .get(&*session_id)
        .await
        .map_err(AppError::paos_internal)?
        .ok_or(PaosError::Timeout)?;
    let (conn_handle, aux_data) = match &session_data.state {
        State::EAC1 {
            conn_handle,
            aux_data,
        } => (conn_handle.clone(), aux_data.clone()),
        _ => return Err(PaosError::Parameter("Expected state EAC1OutputType".into()).into()),
    };
    let body = envelope.into_body();

    // Validate request body
    body.validate().map_err(PaosError::from)?;

    if body.result.is_error() {
        return Err(AppError::paos_internal(PaosError::Parameter(
            "Client respond with error, aborting session".into(),
        )));
    }

    let data = body.data();
    let ecdh_keypair = generate_eph_keypair(&data.card_access)?;

    if data.car.is_some() {
        return Err(AppError::paos_internal(PaosError::Parameter(
            "CertificationAuthorityReference should not be present at this point".into(),
        )));
    }

    // Build DIDAuthenticate with EAC2InputType
    let resp = build_did_auth_eac2(&state, aux_data, &ecdh_keypair, &conn_handle, &data).await?;

    let message_id = uuid::Uuid::new_v4().urn().to_string();
    // remove old message id
    SESSION_TRACKER.invalidate(&id_map);
    SESSION_TRACKER.insert(message_id.clone(), session_id.clone());

    let header = Header {
        relates_to: Some(relates_to),
        message_id: Some(message_id),
    };

    let chat = &data.chat;
    let slot_handle = &conn_handle
        .slot_handle
        .ok_or_else(|| PaosError::Parameter("Missing slot handle".into()))?;
    let serialized_keypair = ecdh_keypair.private_key().to_pkcs8_der()?;

    // Update session state
    session_data.state = State::EAC2 {
        slot_handle: slot_handle.clone(),
        chat: chat.clone(),
        eph_key: serialized_keypair,
    };
    session_mgr.insert(session_id, &session_data).await?;

    resp.validate().map_err(AppError::paos_internal)?;
    let result = Envelope::new(resp).with_header(header).serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

async fn build_did_auth_eac2<T: TrustStore>(
    state: &AppState<T>,
    aux_data: Option<String>,
    ecdh_keypair: &EcdhKeyPair,
    conn_handle: &ConnectionHandle,
    data: &EAC1OutputType,
) -> Result<DidAuthEac2, AppError> {
    let pub_point = ecdh_keypair.public_key().uncompressed_bytes();
    let signature = generate_signature(aux_data, ecdh_keypair, state, data).await?;

    let eac2_input_type = EAC2InputType {
        protocol: EAC2_PROTOCOL_ID.into(),
        type_: Some(EAC2_TYPE.into()),
        certificates: None,
        eph_pubkey: hex::encode(pub_point),
        signature,
    };

    Ok(DidAuthEac2 {
        value: DIDAuthenticate {
            connection_handle: conn_handle.clone(),
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

    let mut tbs_data = Vec::with_capacity(4);
    tbs_data.extend_from_slice(&hex::decode(&data.id_picc)?);
    tbs_data.extend_from_slice(&hex::decode(&data.challenge)?);
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

fn generate_eph_keypair(card_access: &str) -> Result<EcdhKeyPair, AppError> {
    let chip_auth_infos = extract_chip_auth_info(card_access)?;
    let chip_auth_params = find_chip_auth_domain_param_info(card_access)?;

    // Find the first compatible ChipAuthDomainParamInfo.
    // A domain parameter is compatible if it has the same keyId as one of the
    // found ChipAuthenticationInfo, or if the keyId is not present in both.
    let compatible_param = chip_auth_params.iter().find(|(param, _)| {
        chip_auth_infos
            .iter()
            .any(|info| info.key_id == param.key_id)
    });

    if let Some((_, curve)) = compatible_param {
        Ok(EcdhKeyPair::generate_ephemeral(*curve)?)
    } else {
        Err(AppError::Paos(PaosError::Parameter(
            "No compatible domain parameter found".into(),
        )))
    }
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
        AppError::Paos(PaosError::Parameter(error.to_string()))
    }
}
