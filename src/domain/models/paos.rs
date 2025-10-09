pub mod did_auth;
pub mod startpaos;
pub mod transmit;

pub use did_auth::*;
pub use startpaos::*;
pub use transmit::*;

use crate::domain::models::ResultType;
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Decode, Encode)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionHandle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_handle: Option<String>,
    #[serde(rename = "IFDName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifd_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_handle: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct StartPaosResponse {
    pub result: ResultType,
}
