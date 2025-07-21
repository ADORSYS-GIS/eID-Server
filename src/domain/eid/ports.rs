//! interface that external modules use to interact with the domain.

use crate::eid::get_result::error::GetResultError;
use crate::eid::get_result::model::GetResultResponse;
use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use async_trait::async_trait;
use color_eyre::Result;
use std::sync::{Arc, RwLock};

use super::models::{AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ServerInfo};
use super::service::SessionInfo;

#[async_trait]
pub trait EIDService: Clone + Send + Sync + 'static {
    async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;

    // Methods to support separation of concerns
    fn get_sessions(&self) -> &Arc<RwLock<Vec<SessionInfo>>>;
    fn create_get_result_response_from_data(
        &self,
        authentication_data: &str,
    ) -> Result<GetResultResponse, GetResultError>;
}

#[async_trait]
pub trait DIDAuthenticate: Send + Sync {
    async fn handle_did_authenticate(
        &self,
        request: DIDAuthenticateRequest,
    ) -> Result<DIDAuthenticateResponse, AuthError>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
