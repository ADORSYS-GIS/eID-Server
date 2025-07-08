//! Interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use color_eyre::Result;

use super::models::ServerInfo;

pub trait EIDService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
    fn is_session_valid(&self, session_id: &str) -> Result<bool>;
    fn update_session_connection_handles(
        &self,
        session_id: &str,
        connection_handles: Vec<String>,
    ) -> Result<()>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
