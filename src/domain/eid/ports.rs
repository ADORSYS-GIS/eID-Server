//! interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use async_trait::async_trait;
use color_eyre::Result;

use super::models::{AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ServerInfo};

#[async_trait]
pub trait EIDService: Clone + Send + Sync + 'static {
    async fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
    async fn is_session_valid(&self, session_id: &str) -> Result<bool>;
    async fn update_session_connection_handles(
        &self,
        session_id: &str,
        connection_handles: Vec<String>,
    ) -> Result<()>;
}

#[async_trait]
pub trait DIDAuthenticate {
    async fn handle_did_authenticate(
        &self,
        request: DIDAuthenticateRequest,
    ) -> Result<DIDAuthenticateResponse, AuthError>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
