use crate::domain::models::{eid::UseIDRequest, paos::ConnectionHandle};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub request_data: UseIDRequest,
    pub psk: Vec<u8>,
    pub conn_handle: Option<ConnectionHandle>,
}
