pub mod did_auth;
pub mod health;
pub mod startpaos;
pub mod useid;

use std::time::Duration;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use serde::Deserialize;
use startpaos::handle_start_paos;
use tracing::{debug, instrument};
use useid::handle_useid;

use crate::domain::models::eid::UseIDRequest;
use crate::domain::models::paos::{DIDAuthenticateResponse, EAC1OutputType, StartPaosReq};
use crate::pki::truststore::TrustStore;
use crate::server::handlers::did_auth::handle_did_authenticate;
use crate::server::{AppState, errors::AppError};
use crate::soap::Envelope;

use super::responses::SoapResponse;

static SESSION_TRACKER: Lazy<Cache<String, String>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(5 * 60))
        .build()
});

#[derive(Debug, Deserialize)]
enum IncomingReq {
    #[serde(rename = "useIDRequest")]
    UseIDReq(UseIDRequest),
    #[serde(rename = "StartPAOS")]
    StartPaosReq(StartPaosReq),
    #[serde(rename = "DIDAuthenticateResponse")]
    DidAuthRespEAC1(DIDAuthenticateResponse<EAC1OutputType>),
    #[serde(other)]
    Other,
}

#[inline]
async fn wrap_soap(
    fut: impl Future<Output = Result<String, AppError>> + Send,
) -> Result<Response, AppError> {
    fut.await.map(|xml| {
        debug!(xml = %xml, "Sending response\n");
        SoapResponse::new(xml).into_response()
    })
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
    debug!(req = %request, "Processing authentication request\n");

    let envelope = Envelope::<IncomingReq>::parse(&request)?;
    let header = envelope.header().clone().unwrap_or_default();

    match envelope.into_body() {
        IncomingReq::UseIDReq(request) => {
            wrap_soap(handle_useid(
                state,
                Envelope::new(request).with_header(header),
            ))
            .await
        }
        IncomingReq::StartPaosReq(request) => {
            wrap_soap(handle_start_paos(
                state,
                Envelope::new(request).with_header(header),
            ))
            .await
        }
        IncomingReq::DidAuthRespEAC1(request) => {
            wrap_soap(handle_did_authenticate(
                state,
                Envelope::new(request).with_header(header),
            ))
            .await
        }
        IncomingReq::Other => Err(AppError::InvalidRequest("Unsupported request type".into())),
    }
}
