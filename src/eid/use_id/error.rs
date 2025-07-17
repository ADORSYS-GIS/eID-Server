use crate::eid::soap::error::SoapError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UseIdError {
    #[error("Error parsing useIDRequest: {0}")]
    GenericError(String),
}

impl From<SoapError> for UseIdError {
    fn from(error: SoapError) -> Self {
        match error {
            SoapError::DeserializationError { path, message } => {
                UseIdError::GenericError(format!("Failed at {path}: {message}"))
            }
            SoapError::MissingElement(elem) => {
                UseIdError::GenericError(format!("Missing element: {elem}"))
            }
            SoapError::InvalidElement { path, message } => {
                UseIdError::GenericError(format!("Invalid element at {path}: {message}"))
            }
            SoapError::SerializationError(msg) => UseIdError::GenericError(msg),
        }
    }
}
