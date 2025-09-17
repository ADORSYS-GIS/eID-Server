use crate::domain::models::eid::UseIDRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionData {
    pub request_data: UseIDRequest,
    pub psk: Vec<u8>,
}
