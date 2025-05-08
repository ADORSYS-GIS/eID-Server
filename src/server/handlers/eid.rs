use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::{
    domain::eid::ports::EidService,
    server::{AppState, responses::Xml},
};

/// Handler for the /eIDService/getServerInfo endpoint
/// Returns information about the eID-Server capabilities and version
pub(crate) async fn get_server_info<S: EidService>(
    State(state): State<AppState<S>>,
) -> impl IntoResponse {
    let server_info = state.eid_service.get_server_info();
    (StatusCode::OK, Xml(server_info))
}
