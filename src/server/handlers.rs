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
use crate::domain::models::paos::StartPaosReq;
use crate::server::{AppState, errors::AppError};
use crate::session::SessionStore;
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
}

#[inline]
fn wrap_soap(
    fut: impl Future<Output = Result<String, AppError>> + Send,
) -> impl Future<Output = Result<Response, AppError>> {
    async move { fut.await.map(|xml| SoapResponse::new(xml).into_response()) }
}

/// Processes an incoming request and routes to the appropriate handler
#[instrument(skip(state, request))]
pub async fn process_authentication<S>(
    State(state): State<AppState<S>>,
    request: String,
) -> Result<Response, AppError>
where
    S: SessionStore,
{
    debug!(req = %request, "Processing authentication request");

    let envelope = Envelope::<IncomingReq>::parse(&request)?;
    match envelope.into_body() {
        IncomingReq::UseIDReq(request) => {
            wrap_soap(handle_useid(state, Envelope::new(request))).await
        }
        IncomingReq::StartPaosReq(request) => {
            wrap_soap(handle_start_paos(state, Envelope::new(request))).await
        }
    }
}
