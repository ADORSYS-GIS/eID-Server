pub mod eid;
pub mod paos;

use bincode::{Decode, Encode};
use paos::ConnectionHandle;
use serde::{Deserialize, Serialize};

use crate::{asn1::utils::ChipAuthAlg, crypto::Curve};

pub const RESULT_OK: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok";
pub const RESULT_ERROR: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error";

/// Result type for error handling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResultType {
    pub result_major: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_minor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
}

impl ResultType {
    pub fn ok() -> Self {
        Self {
            result_major: RESULT_OK.into(),
            result_minor: None,
            result_message: None,
        }
    }

    pub fn error(error_code: &str, message: Option<&str>) -> Self {
        Self {
            result_major: RESULT_ERROR.into(),
            result_minor: Some(error_code.into()),
            result_message: message.map(|s| s.into()),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.result_major == RESULT_OK
    }

    pub fn is_error(&self) -> bool {
        self.result_major == RESULT_ERROR
    }
}

#[derive(Debug, Clone, Decode, Encode)]
pub enum State {
    Initial,
    EAC1 {
        conn_handle: ConnectionHandle,
        aux_data: Option<String>,
    },
    EAC2 {
        slot_handle: String,
        chat: Option<String>,
        eph_key: Vec<u8>,
        chip_auth: (Curve, ChipAuthAlg),
    },
}
