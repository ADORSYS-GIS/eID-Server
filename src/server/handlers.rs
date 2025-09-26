pub mod health;
pub mod useid;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::{debug, instrument};
use useid::handle_useid;

use crate::domain::models::eid::UseIDRequest;
use crate::pki::truststore::TrustStore;
use crate::server::{AppState, errors::AppError};
use crate::soap::Envelope;

use super::responses::SoapResponse;

#[derive(Debug, Deserialize)]
enum IncomingReq {
    #[serde(rename = "useIDRequest")]
    UseID(UseIDRequest),
    #[serde(other)]
    Other,
}

#[inline]
fn soap_ok(xml: String) -> Response {
    SoapResponse::new(xml).into_response()
}

/// Processes an incoming request and routes to the appropriate handler
#[instrument(skip(state, request))]
pub async fn process_authentication<T>(
    State(state): State<AppState<T>>,
    request: String,
) -> Result<Response, AppError>
where
    T: TrustStore,
{
    debug!("Processing request: {request}");

    let envelope = Envelope::<IncomingReq>::parse(&request)?;
    let body = envelope.into_body();

    match body {
        IncomingReq::UseID(req) => {
            let envelope = Envelope::new(req);
            handle_useid(state, envelope).await.map(soap_ok)
        }
        IncomingReq::Other => Err(AppError::SchemaViolation(
            "Unsupported request type".to_string(),
        )),
    }
}
