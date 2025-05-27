//! interface that external modules use to interact with the domain.

use crate::eid::use_id::model::{UseIDRequest, UseIDResponse};
use color_eyre::Result;

use super::models::ServerInfo;

pub trait EIDService: Clone + Send + Sync + 'static {
    fn handle_use_id(&self, request: UseIDRequest) -> Result<UseIDResponse>;
}

pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
