//! interface that external modules use to interact with the domain.

use super::models::ServerInfo;

// Updated trait with getServerInfo method
pub trait EidService: Clone + Send + Sync + 'static {
    /// Returns information about the eID-Server
    fn get_server_info(&self) -> ServerInfo;
}
