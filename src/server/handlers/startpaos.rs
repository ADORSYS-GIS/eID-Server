use rasn::types::NumericString;
use serde::Serialize;
use time::UtcDateTime;
use time::format_description::parse;
use validator::Validate;

use crate::asn1::auth_data::{AuthenticatedAuxiliaryData, Date};
use crate::asn1::cvcert::Chat;
use crate::cvcert::{AccessRight, AccessRights, AccessRole};
use crate::domain::models::State;
use crate::domain::models::eid::AttributeReq;
use crate::domain::models::paos::{
    AuthProtoData, ConnectionHandle, DIDAuthenticate, EAC1InputType, StartPaosReq,
};
use crate::pki::{identity::Material, truststore::TrustStore};
use crate::server::errors::impl_paos_internal_error;
use crate::server::handlers::{SESSION_TRACKER, handle_paos_error};
use crate::server::{
    AppState,
    errors::{AppError, PaosError},
};
use crate::session::{SessionData, SessionManager};
use crate::soap::{Envelope, Header};

const DID_NAME: &str = "PIN";
const EAC1_TYPE: &str = "EAC1InputType";
/// Known Application Identifiers for supported card applications
const KNOWN_AIDS: &[&str] = &["E80704007F00070302"];
const EAC2_PROTOCOL_ID: &str = "urn:oid:1.3.162.15480.3.0.14.2";

#[derive(Debug, Serialize, Validate)]
struct DidAuthEac1 {
    #[validate(nested)]
    #[serde(rename = "DIDAuthenticate")]
    value: DIDAuthenticate<EAC1InputType>,
}

pub async fn handle_start_paos<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<StartPaosReq>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let session_id = envelope.body().session_identifier.clone();

    match handle_inner(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_paos_error(session_mgr, &session_id, e).await,
    }
}

async fn handle_inner<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<StartPaosReq>,
) -> Result<String, AppError> {
    let relates_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());

    let session_mgr = &state.service.session_manager;
    let body = envelope.into_body();
    let session_id = body.session_identifier.as_str();

    // Validate request body
    body.validate().map_err(PaosError::from)?;

    // Retrieve and validate session
    let mut session_data = get_and_validate_session(session_mgr, session_id, &body).await?;

    // Get supported connection handle
    let conn_handle = body
        .select_connection_handle(KNOWN_AIDS)
        .ok_or(PaosError::Parameter("Unsupported card application".into()))?;

    // Build DIDAuthenticate with EAC1InputType
    let resp = build_did_auth_eac1(state, &session_data, conn_handle).await?;

    let message_id = uuid::Uuid::new_v4().urn().to_string();
    SESSION_TRACKER.insert(message_id.clone(), session_id.into());

    let header = Header {
        relates_to: Some(relates_to),
        message_id: Some(message_id),
    };

    // Update session state
    let aux_data = &resp.value.auth_protocol_data.data.auth_aux_data;
    let required_chat = build_required_chat(&session_data);
    let optional_chat = build_optional_chat(&session_data);
    session_data.state = State::EAC1 {
        conn_handle: conn_handle.clone(),
        aux_data: aux_data.clone(),
        built_chat: (required_chat, optional_chat),
    };
    session_mgr.insert(session_id, &session_data).await?;

    resp.validate().map_err(AppError::paos_internal)?;
    let result = Envelope::new(resp).with_header(header).serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

/// Retrieves session and validates it meets requirements for StartPAOS
async fn get_and_validate_session(
    session_mgr: &SessionManager,
    session_id: &str,
    body: &StartPaosReq,
) -> Result<SessionData, AppError> {
    // Ensure session exists
    let session_data: SessionData = session_mgr
        .get(session_id)
        .await?
        .ok_or(PaosError::MissingPermissions)?;

    // Validate API version compatibility
    if !body.supported_api_versions.iter().any(|v| v.is_compliant()) {
        return Err(PaosError::Parameter("Non-compliant API version".into()).into());
    }
    // Check session state
    if !matches!(session_data.state, State::Initial) {
        return Err(PaosError::Parameter("Expected state StartPAOS".into()).into());
    }
    Ok(session_data)
}

async fn build_did_auth_eac1<T: TrustStore>(
    state: &AppState<T>,
    session_data: &SessionData,
    conn_handle: &ConnectionHandle,
) -> Result<DidAuthEac1, AppError> {
    let identity = &state.service.identity;
    let (term_cvc, dv_cvc, cert_desc_bytes) = tokio::try_join!(
        identity.get(Material::TermCvc),
        identity.get(Material::DvCvc),
        identity.get(Material::CertDesc)
    )?;

    let eac1_input_type = EAC1InputType {
        protocol: EAC2_PROTOCOL_ID.into(),
        type_: Some(EAC1_TYPE.into()),
        certificates: vec![hex::encode(dv_cvc), hex::encode(term_cvc)],
        cert_description: hex::encode(cert_desc_bytes),
        auth_aux_data: build_auth_aux_data(session_data)?,
        required_chat: build_required_chat(session_data),
        optional_chat: build_optional_chat(session_data),
        transaction_info: session_data.request_data.transaction_info.clone(),
    };

    Ok(DidAuthEac1 {
        value: DIDAuthenticate {
            connection_handle: conn_handle.clone(),
            did_scope: None,
            did_name: DID_NAME.into(),
            auth_protocol_data: AuthProtoData {
                data: eac1_input_type,
            },
        },
    })
}

fn build_auth_aux_data(session_data: &SessionData) -> Result<Option<String>, AppError> {
    let mut aux = AuthenticatedAuxiliaryData::new();

    if let Some(age_verif) = &session_data.request_data.age_verification {
        let now = UtcDateTime::now().date();
        let req_date = now.replace_year(now.year() - age_verif.age)?;
        let dob_str = req_date.format(&parse("[year][month][day]")?)?;
        let dob = NumericString::from_bytes(dob_str.as_bytes()).map_err(AppError::paos_internal)?;
        aux.add_date_of_birth(Date(dob))?;
    }

    if let Some(comm_id) = &session_data.request_data.place_verification {
        aux.add_municipality_id(comm_id.community_id.as_bytes())?;
    }

    if aux.is_empty() {
        Ok(None)
    } else {
        Ok(Some(aux.to_hex()?))
    }
}

fn build_required_chat(session_data: &SessionData) -> Option<String> {
    build_chat(session_data, |op| op.is_required())
}

fn build_optional_chat(session_data: &SessionData) -> Option<String> {
    build_chat(session_data, |op| op.is_allowed())
}

fn build_chat(
    session_data: &SessionData,
    predicate: impl Fn(&AttributeReq) -> bool,
) -> Option<String> {
    let mut rights = AccessRights::new();
    let ops = &session_data.request_data.use_operations;

    let attribute_mappings = [
        (&ops.document_type, AccessRight::ReadDG01),
        (&ops.issuing_state, AccessRight::ReadDG02),
        (&ops.date_of_expiry, AccessRight::ReadDG03),
        (&ops.given_names, AccessRight::ReadDG04),
        (&ops.family_names, AccessRight::ReadDG05),
        (&ops.artistic_name, AccessRight::ReadDG06),
        (&ops.academic_title, AccessRight::ReadDG07),
        (&ops.date_of_birth, AccessRight::ReadDG08),
        (&ops.place_of_birth, AccessRight::ReadDG09),
        (&ops.nationality, AccessRight::ReadDG10),
        (&ops.birth_name, AccessRight::ReadDG13),
        (&ops.place_of_residence, AccessRight::ReadDG17),
        (&ops.community_id, AccessRight::ReadDG18),
        (&ops.residence_permit_i, AccessRight::ReadDG19),
        (&ops.restricted_id, AccessRight::RestrictedIdentification),
    ];

    for (attr_req, access_right) in attribute_mappings.iter() {
        if predicate(attr_req) {
            rights.add(*access_right);
        }
    }

    // Add special verification functions
    let operations = &session_data.request_data.use_operations;
    if !operations.age_verification.is_prohibited() {
        rights.add(AccessRight::AgeVerification);
    }
    if !operations.place_verification.is_prohibited() {
        rights.add(AccessRight::CommunityIdVerification);
    }

    if rights.rights().is_empty() {
        None
    } else {
        Some(Chat::new(rights.to_chat_template(AccessRole::AT)).to_hex())
    }
}

impl_paos_internal_error! {
    time::error::InvalidFormatDescription,
    time::error::ComponentRange,
    time::error::Format,
    rasn::error::EncodeError,
}
