//! interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use async_trait::async_trait;
use color_eyre::Result;

use super::models::{AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ServerInfo};

pub trait EIDService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
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
