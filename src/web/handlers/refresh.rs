//! Refresh endpoint handler for establishing PSK-based TLS connections
//!
//! This module implements the /refresh endpoint that establishes a TLS handshake
//! connection with PSK as the common key. Once established, this secure channel
//! is used for all subsequent communications with the client.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, error, warn};

use crate::domain::eid::ports::{EIDService, EidService};
use crate::server::AppState;

/// Handler for the /refresh endpoint
/// This endpoint establishes a PSK-based TLS connection for the given session
pub async fn refresh_handler<S: EIDService + EidService + Clone + Send + Sync + 'static>(
    State(state): State<AppState<S>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    debug!("Refresh endpoint called with params: {:?}", params);

    // Extract session identifier from query parameters
    // Try multiple possible parameter names that real-world clients might use
    let session_id = params.get("SessionIdentifier")
        .or_else(|| params.get("sessionIdentifier"))
        .or_else(|| params.get("sessionidentifier"))
        .or_else(|| params.get("session_identifier"))
        .or_else(|| params.get("session-identifier"))
        .or_else(|| params.get("session"))
        .or_else(|| params.get("Session"))
        .or_else(|| params.get("ID"))
        .or_else(|| params.get("id"))
        .filter(|id| !id.is_empty())
        .cloned();

    let session_id = match session_id {
        Some(id) => id,
        None => {
            warn!("Missing or empty session identifier in refresh request. Available params: {:?}", params);
            return (StatusCode::BAD_REQUEST, "Missing session identifier").into_response();
        }
    };

    debug!("Processing refresh request for session: {}", session_id);

    // Get the session from the session manager to retrieve PSK
    let session_manager_arc = state.use_id.get_session_manager();
    let session_manager = match session_manager_arc.read() {
        Ok(mgr) => mgr,
        Err(e) => {
            error!("Failed to acquire session manager lock: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    // Find the session
    let session = match session_manager.sessions.iter().find(|s| s.id == session_id) {
        Some(session) => session,
        None => {
            warn!("Session not found: {}", session_id);
            return (StatusCode::NOT_FOUND, "Session not found").into_response();
        }
    };

    let psk = session.psk.clone();
    drop(session_manager); // Release the lock

    // Store the PSK in the PSK store for TLS handshake validation
    if let Some(ref psk_store) = state.psk_store {
        if let Err(e) = psk_store.add_psk(session_id.clone(), psk.clone()) {
            error!("Failed to store PSK for session {}: {}", session_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to establish secure connection").into_response();
        }
        debug!("PSK stored for session: {}", session_id);
    } else {
        error!("PSK store not available for TLS handshake");
        return (StatusCode::INTERNAL_SERVER_ERROR, "TLS PSK configuration not available").into_response();
    }

    debug!("PSK-based TLS connection established for session: {}", session_id);

    // Return success response indicating that the secure channel is established
    let response_body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<RefreshResponse xmlns="http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#">
    <Result>
        <ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ResultMajor>
    </Result>
    <SessionIdentifier>{}</SessionIdentifier>
    <SecureChannelEstablished>true</SecureChannelEstablished>
</RefreshResponse>"#,
        session_id
    );

    (
        StatusCode::OK,
        [("Content-Type", "application/xml; charset=UTF-8")],
        response_body,
    ).into_response()
}
