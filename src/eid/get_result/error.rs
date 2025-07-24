use crate::eid::soap::error::{ErrorKind, SoapError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GetResultError {
    #[error("Error parsing getResultRequest: {0}")]
    GenericError(String),
    #[error("Request still has not been completed")]
    NoResultYet,
    #[error("Used session ID is invalid")]
    InvalidSession,
    #[error("RequestCounter is incremented incorrectly")]
    InvalidRequestCounter,
    #[error("Used eId-Document did not match level of assurance or has been denied")]
    DeniedDocument,
    #[error("Used eID-Document is invalid")]
    InvalidDocument,
}

impl From<SoapError> for GetResultError {
    fn from(error: SoapError) -> Self {
        match error {
            SoapError::XmlError {
                kind,
                path,
                message,
            } => match kind {
                ErrorKind::Deserialization => {
                    GetResultError::GenericError(format!("Failed at {path:?}: {message}"))
                }
                ErrorKind::MissingElement => {
                    GetResultError::GenericError(format!("Missing element: {message}"))
                }
                ErrorKind::InvalidElement => {
                    GetResultError::GenericError(format!("Invalid element at {path:?}: {message}"))
                }
                ErrorKind::Serialization => GetResultError::GenericError(message),
            },
        }
    }
}
