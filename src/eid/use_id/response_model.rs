use crate::common::models::ResultCode;

pub struct UseIDResponse {
    pub session: String,
    pub ecard_server_address: Option<String>,
    pub psk: Option<String>,
    pub result: ResultCode,
}
