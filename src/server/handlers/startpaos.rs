use rasn::types::NumericString;
use serde::Serialize;
use time::UtcDateTime;
use tracing::instrument;
use validator::Validate;

use crate::asn1::auth_data::Date;
use crate::domain::models::paos::{DIDAuthenticate, EAC1InputType};
use crate::domain::models::{
    ResultType,
    paos::{ConnectionHandle, StartPaosReq, StartPaosResponse},
};
use crate::server::{
    AppState,
    errors::{AppError, PaosError},
};
use crate::session::{SessionData, SessionManager, SessionStore};
use crate::soap::Envelope;

const DID_NAME: &str = "PIN";
const KNOWN_AIDS: &[&str] = &["E80704007F00070302"];
const EAC2_PROTOCOL_ID: &str = "urn:oid:1.3.162.15480.3.0.14.2";

#[derive(Debug, Serialize)]
struct StartPaosResp {
    #[serde(rename = "StartPAOSResponse")]
    resp: StartPaosResponse,
}

#[derive(Debug, Serialize, Validate)]
struct DidAuthEac1 {
    #[validate(nested)]
    #[serde(rename = "DIDAuthenticate")]
    value: DIDAuthenticate<EAC1InputType>,
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

async fn fail<S: SessionStore, E: Into<AppError>>(
    session_mgr: &SessionManager<S>,
    session_id: &str,
    error: E,
) -> Result<String, AppError> {
    let _ = session_mgr.remove(session_id).await;
    let env = Envelope::new(StartPaosResp::error(error));
    env.serialize_paos(true).map_err(AppError::paos_internal)
}

pub async fn handle_start_paos<S: SessionStore>(
    state: AppState<S>,
    envelope: Envelope<StartPaosReq>,
) -> Result<String, AppError> {
    let relate_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or(uuid::Uuid::new_v4().urn().to_string());
    let session_mgr = state.service.session_manager;
    let body = envelope.into_body();
    let session_id = body.session_identifier.as_str();

    // Validate request body
    if let Err(e) = body.validate() {
        return fail(&session_mgr, session_id, AppError::Paos(e.into())).await;
    }

    // Ensure session exists
    if !session_mgr
        .exists(session_id)
        .await
        .map_err(AppError::paos_internal)?
    {
        return fail(&session_mgr, session_id, PaosError::MissingPermissions).await;
    }

    // Ensure compliant API version
    if !body.supported_api_versions.iter().any(|v| v.is_compliant()) {
        return fail(
            &session_mgr,
            session_id,
            PaosError::Parameter("Failed to find compliant API version".into()),
        )
        .await;
    }

    // Ensure supported connection handle
    let Some(connection_handle) = body.select_connection_handle(KNOWN_AIDS) else {
        return fail(
            &session_mgr,
            session_id,
            PaosError::Parameter("Unsupported card application".into()),
        )
        .await;
    };
    let Some(mut session_data) = session_mgr
        .get::<SessionData>(session_id)
        .await
        .map_err(AppError::paos_internal)?
    else {
        return fail(&session_mgr, session_id, PaosError::Timeout).await;
    };

    // Update connection handle and save back
    session_data.conn_handle = Some(connection_handle.clone());
    session_mgr
        .insert(session_id, &session_data)
        .await
        .map_err(AppError::paos_internal)?;

    // Build and return DIDAuthenticate with EAC1InputType
    build_did_auth_eac1(&mut session_data, session_id, &connection_handle)
        .await
        .map_err(AppError::paos_internal)
}

async fn build_did_auth_eac1(
    session_data: &mut SessionData,
    session_id: &str,
    conn_handle: &ConnectionHandle,
) -> Result<String, AppError> {
    Ok(String::new())
}

impl Date {
    /// Create a new Date from a string in YYYYMMDD format
    pub fn new(date_str: &str) -> Result<Self, &'static str> {
        if date_str.len() != 8 {
            return Err("Date must be exactly 8 characters (YYYYMMDD)");
        }

        // Validate that all characters are digits
        if !date_str.chars().all(|c| c.is_ascii_digit()) {
            return Err("Date must contain only digits");
        }

        Ok(Date(
            NumericString::from_bytes(date_str.as_bytes()).unwrap(),
        ))
    }
}
