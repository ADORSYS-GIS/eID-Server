pub mod health;
pub mod useid;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::instrument;
use useid::handle_useid;

use crate::domain::models::eid::UseIDRequest;
use crate::server::{AppState, errors::AppError};
use crate::session::SessionStore;
use crate::soap::Envelope;

use super::responses::SoapResponse;

#[derive(Debug, Deserialize)]
enum IncomingReq {
    #[serde(rename = "useIDRequest")]
    UseID(UseIDRequest),
}

#[inline]
fn soap_ok(xml: String) -> Response {
    SoapResponse::new(xml).into_response()
}

/// Processes an incoming request and routes to the appropriate handler
#[instrument(skip(state))]
pub async fn process_authentication<S>(
    State(state): State<AppState<S>>,
    request: String,
) -> Result<Response, AppError>
where
    S: SessionStore,
{
    let envelope = Envelope::<IncomingReq>::parse(&request)?;
    let body = envelope.into_body();

    match body {
        IncomingReq::UseID(req) => {
            let envelope = Envelope::new(req);
            handle_useid(state, envelope).await.map(soap_ok)
        }
    }
}
