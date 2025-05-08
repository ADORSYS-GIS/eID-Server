//! Service layer that provides the business logic of the domain.

use super::{models::ServerInfo, ports::EidService};

#[derive(Debug, Clone)]
pub struct Service;

impl Service {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

impl EidService for Service {
    fn get_server_info(&self) -> ServerInfo {
        // Return default ServerInfo which contains the basic implementation details
        ServerInfo::default()
    }
}
