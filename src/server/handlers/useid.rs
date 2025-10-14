use serde::Serialize;
use tracing::instrument;
use validator::Validate;

use crate::crypto::generate_random_bytes;
use crate::domain::models::State;
use crate::domain::models::{
    ResultType,
    eid::{PreSharedKey, Session, UseIDRequest, UseIDResponse},
};
use crate::pki::truststore::TrustStore;
use crate::server::{
    AppState,
    errors::{AppError, EidError},
};
use crate::session::{SessionData, SessionError};
use crate::soap::Envelope;

#[derive(Debug, Serialize, Validate)]
struct UseIDResp {
    #[serde(rename = "eid:useIDResponse")]
    #[validate(nested)]
    value: UseIDResponse,
}

#[instrument(skip(state, envelope))]
pub async fn handle_useid<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<UseIDRequest>,
) -> Result<String, AppError> {
    let body = envelope.into_body();
    validate_request(&body)?;

    let (id, key) = if let Some(ref psk) = body.psk {
        if psk.validate().is_err() {
            return Err(EidError::InvalidPSK.into());
        }
        let key = hex::decode(&psk.key).map_err(|_| EidError::InvalidPSK)?;
        (psk.id.clone(), key)
    } else {
        let id = hex::encode(generate_random_bytes(16));
        let key = generate_random_bytes(32);
        (id, key)
    };

    let session_data = SessionData {
        request_data: body,
        request_counter: 0,
        psk: key.clone(),
        state: State::Initial,
    };

    match state
        .service
        .session_manager
        .insert(&*id, session_data)
        .await
    {
        Ok(_) => build_response(id, key),
        Err(SessionError::MaxSessions) => Err(EidError::TooManyOpenSessions.into()),
        Err(e) => Err(AppError::soap_internal(e)),
    }
}

fn validate_request(body: &UseIDRequest) -> Result<(), AppError> {
    body.validate().map_err(EidError::from)?;

    if body.age_verification.is_none() && !body.use_operations.age_verification.is_prohibited() {
        return Err(EidError::MissingArgument("AgeVerification".into()).into());
    }
    if body.place_verification.is_none() && !body.use_operations.place_verification.is_prohibited()
    {
        return Err(EidError::MissingArgument("PlaceVerification".into()).into());
    }
    Ok(())
}

fn build_response(session_id: String, psk: Vec<u8>) -> Result<String, AppError> {
    let resp = UseIDResp {
        value: UseIDResponse {
            session: Session {
                id: session_id.clone(),
            },
            e_card_address: None,
            psk: PreSharedKey {
                id: session_id,
                key: hex::encode(psk),
            },
            result: ResultType::ok(),
        },
    };
    resp.validate().map_err(AppError::soap_internal)?;
    let result = Envelope::new(resp).serialize_soap(true);
    result.map_err(AppError::soap_internal)
}
