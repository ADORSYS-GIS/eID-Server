//! interface that external modules use to interact with the domain.

use std::sync::{Arc, RwLock};

use crate::{
    domain::eid::service::{EIDServiceConfig, SessionManager},
    eid::use_id::model::{UseIDRequest, UseIDResponse},
};
use color_eyre::Result;
use async_trait::async_trait;

use super::models::{AuthError, DIDAuthenticateRequest, DIDAuthenticateResponse, ServerInfo};

pub trait EIDService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;

    fn is_session_valid(&self, session_id: &str) -> Result<bool>;
    fn get_use_id_service(&self) -> Self;
    fn get_session_manager(&self) -> Arc<RwLock<SessionManager>>;
    fn get_config(&self) -> EIDServiceConfig;
}

#[async_trait]
pub trait DIDAuthenticate: Send + Sync {
    async fn handle_did_authenticate(&self, request: DIDAuthenticateRequest) -> Result<DIDAuthenticateResponse, AuthError>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
