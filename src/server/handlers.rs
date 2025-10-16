pub mod did_auth;
pub mod getresult;
pub mod health;
pub mod server_info;
pub mod startpaos;
pub mod transmit;
pub mod useid;

use std::time::Duration;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use getresult::handle_get_result;
use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use server_info::handle_get_server_info;
use startpaos::handle_start_paos;
use tracing::{debug, instrument};
use useid::handle_useid;

use crate::domain::models::paos::StartPaosResponse;
use crate::pki::truststore::TrustStore;
use crate::server::handlers::did_auth::{handle_did_auth_eac1, handle_did_auth_eac2};
use crate::server::handlers::transmit::handle_transmit;
use crate::server::responses::SoapResponse;
use crate::server::{AppState, errors::AppError};
use crate::session::SessionManager;
use crate::soap::Envelope;

static SESSION_TRACKER: Lazy<Cache<String, String>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(100)
        .time_to_live(Duration::from_secs(5 * 60))
        .build()
});

#[derive(Debug, Serialize)]
struct StartPaosResp {
    #[serde(rename = "StartPAOSResponse")]
    resp: StartPaosResponse,
}

impl StartPaosResp {
    pub fn error<T: Into<AppError>>(error: T) -> Self {
        Self {
            resp: StartPaosResponse {
                result: error.into().to_result(),
            },
        }
    }

    pub fn ok() -> Self {
        Self {
            resp: StartPaosResponse::ok(),
        }
    }
}

async fn handle_paos_error<E: Into<AppError>>(
    session_mgr: &SessionManager,
    session_id: &str,
    error: E,
) -> Result<String, AppError> {
    if let Err(e) = session_mgr.remove(session_id).await {
        tracing::warn!("Failed to remove session {session_id}: {e:?}");
    }
    let env = Envelope::new(StartPaosResp::error(error));
    env.serialize_paos(true).map_err(AppError::paos_internal)
}

#[derive(Debug)]
enum APIFunction {
    UseIDRequest,
    StartPaos,
    DidAuthEAC1,
    DidAuthEAC2,
    Transmit,
    GetResult,
    GetServerInfo,
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

    let request_type = infer_request_type(&request)?;
    match request_type {
        APIFunction::UseIDRequest => {
            process_request(state, &request, |s, e| handle_useid(s, e)).await
        }
        APIFunction::GetResult => {
            process_request(state, &request, |s, e| handle_get_result(s, e)).await
        }
        APIFunction::StartPaos => {
            process_request(state, &request, |s, e| handle_start_paos(s, e)).await
        }
        APIFunction::DidAuthEAC1 => {
            process_request(state, &request, |s, e| handle_did_auth_eac1(s, e)).await
        }
        APIFunction::DidAuthEAC2 => {
            process_request(state, &request, |s, e| handle_did_auth_eac2(s, e)).await
        }
        APIFunction::Transmit => {
            process_request(state, &request, |s, e| handle_transmit(s, e)).await
        }
        APIFunction::GetServerInfo => {
            process_request(state, &request, |s, e| handle_get_server_info(s, e)).await
        }
    }
}

fn infer_request_type(xml: &str) -> Result<APIFunction, AppError> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = vec![];
    let mut found_did_auth = false;
    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"useIDRequest" => return Ok(APIFunction::UseIDRequest),
                b"StartPAOS" => return Ok(APIFunction::StartPaos),
                b"DIDAuthenticateResponse" => found_did_auth = true,
                b"AuthenticationProtocolData" if found_did_auth => {
                    for attr in e.attributes().flatten() {
                        let val = attr
                            .unescape_value()
                            .map_err(|_| AppError::InvalidRequest)?;
                        if attr.key.local_name().as_ref() == b"type" {
                            if val.ends_with("EAC1OutputType") {
                                return Ok(APIFunction::DidAuthEAC1);
                            } else if val.ends_with("EAC2OutputType") {
                                return Ok(APIFunction::DidAuthEAC2);
                            }
                        }
                    }
                }
                b"TransmitResponse" => return Ok(APIFunction::Transmit),
                b"getResultRequest" => return Ok(APIFunction::GetResult),
                b"getServerInfoRequest" => return Ok(APIFunction::GetServerInfo),
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Err(AppError::InvalidRequest)
}

async fn process_request<T, R, H, Fut>(
    state: AppState<T>,
    request: &str,
    handler: H,
) -> Result<Response, AppError>
where
    T: TrustStore,
    R: for<'de> Deserialize<'de>,
    H: FnOnce(AppState<T>, Envelope<R>) -> Fut,
    Fut: Future<Output = Result<String, AppError>> + Send,
{
    let envelope = Envelope::<R>::parse(request)?;
    handler(state, envelope).await.map(|xml| {
        debug!(xml = %xml, "Sending response\n");
        SoapResponse::new(xml).into_response()
    })
}
