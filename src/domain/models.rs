pub mod eid;
pub mod errors;

use serde::Serialize;

pub const RESULT_OK: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok";
pub const RESULT_ERROR: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error";
pub const RESULT_MINOR_PREFIX: &str = "http://www.bsi.bund.de/eid/server/2.0/resultminor/";

/// Result type for error handling
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

    pub fn error(minor: &str, message: Option<&str>) -> Self {
        Self {
            result_major: RESULT_ERROR.into(),
            result_minor: Some(format!("{RESULT_MINOR_PREFIX}{minor}")),
            result_message: message.map(|s| s.into()),
        }
    }
}
