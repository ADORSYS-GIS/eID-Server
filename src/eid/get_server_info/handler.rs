use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};

use crate::{
    domain::eid::ports::{EIDService, EidService},
    eid::{
        common::models::AttributeSelection,
        get_server_info::{
            builder::build_get_server_info_response,
            model::{GetServerInfoResponse, OperationsSelector, VersionType},
        },
    },
    server::AppState,
};

fn convert_to_soap_model(
    server_info: crate::domain::eid::models::ServerInfo,
) -> GetServerInfoResponse {
    // Parse version components (e.g., "0.1.0" -> 0, 1, 0)
    let version_parts: Vec<u8> = server_info
        .version
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect();
    let (major, minor, bugfix) = match version_parts.as_slice() {
        [a, b, c] => (*a, *b, *c),
        _ => (0, 0, 0),
    };
    GetServerInfoResponse {
        server_version: VersionType {
            version_string: server_info.server_version,
            major,
            minor,
            bugfix,
        },
        document_verification_rights: OperationsSelector {
            document_type: AttributeSelection::PROHIBITED,
            issuing_state: AttributeSelection::PROHIBITED,
            date_of_expiry: AttributeSelection::PROHIBITED,
            given_names: AttributeSelection::PROHIBITED,
            family_names: AttributeSelection::PROHIBITED,
            artistic_names: AttributeSelection::PROHIBITED,
            academic_title: AttributeSelection::PROHIBITED,
            date_of_birth: AttributeSelection::PROHIBITED,
            place_of_birth: AttributeSelection::PROHIBITED,
            nationality: AttributeSelection::PROHIBITED,
            birth_name: AttributeSelection::PROHIBITED,
            place_of_residence: AttributeSelection::PROHIBITED,
            community_id: None,
            residence_permit_i: None,
            restricted_id: AttributeSelection::PROHIBITED,
            age_verification: AttributeSelection::PROHIBITED,
            place_verification: AttributeSelection::PROHIBITED,
        },
    }
}

/// Handler for the /eIDService/getServerInfo endpoint
/// Handler for the /eIDService/getServerInfo endpoint
/// Returns information about the eID-Server capabilities and version
pub(crate) async fn get_server_info<S>(State(state): State<AppState<S>>) -> impl IntoResponse
where
    S: EIDService + EidService,
{
    let server_info = state.eid_service.get_server_info();
    let soap_response = convert_to_soap_model(server_info);
    let xml =
        build_get_server_info_response(&soap_response).unwrap_or_else(|_| "<error/>".to_string());
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        )],
        xml,
    )
}
