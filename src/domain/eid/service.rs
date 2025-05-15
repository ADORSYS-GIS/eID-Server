//! Service layer that provides the business logic of the domain.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

use super::ports::EidService;

// TODO : Implement the service layer.
#[derive(Debug, Clone)]
pub struct Service<UseID: EidService> {
    eid_service: Arc<UseID>,
}

// Will need to implement this later
// impl Service {
//     pub fn new() -> Self {
//         Self
//     }
// }

// impl Default for Service {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// Configuration for the eID Service
#[derive(Clone, Debug)]
pub struct EIDServiceConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Session timeout in minutes
    pub session_timeout_minutes: i64,
    /// Optional eCard server address to return in responses
    pub ecard_server_address: Option<String>,
}

impl Default for EIDServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout_minutes: 5,
            ecard_server_address: None,
        }
    }
}

/// Session information stored by the server
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub id: String,
    pub expiry: DateTime<Utc>,
    pub psk: Option<String>,
    pub operations: Vec<String>,
}

/// Main service for handling useID requests
#[derive(Clone, Debug)]
pub struct EIDService {
    pub config: EIDServiceConfig,
    pub sessions: Arc<RwLock<Vec<SessionInfo>>>,
}

impl EIDService {
    pub fn new(config: EIDServiceConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }
}
