use crate::domain::models::{State, eid::UseIDRequest};
use bincode::{Decode, Encode};

#[derive(Debug, Decode, Encode)]
pub struct SessionData {
    pub request_data: UseIDRequest,
    pub psk: Vec<u8>,
    pub state: State,
}
