use thiserror::Error;
use crate::eid::soap::error::SoapError;

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
            SoapError::DeserializationError { path, message } => {
                GetResultError::GenericError(format!("Failed at {path}: {message}"))
            }
            SoapError::MissingElement(elem) => {
                GetResultError::GenericError(format!("Missing element: {elem}"))
            }
            SoapError::InvalidElement { path, message } => {
                GetResultError::GenericError(format!("Invalid element at {path}: {message}"))
            }
            SoapError::SerializationError(msg) => GetResultError::GenericError(msg),
        }
    }
}