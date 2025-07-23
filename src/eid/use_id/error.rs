use crate::eid::soap::error::{ErrorKind, SoapError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UseIdError {
    #[error("Error parsing useIDRequest: {0}")]
    GenericError(String),
}

impl From<SoapError> for UseIdError {
    fn from(error: SoapError) -> Self {
        match error {
            SoapError::XmlError {
                kind,
                path,
                message,
            } => match kind {
                ErrorKind::Deserialization => {
                    UseIdError::GenericError(format!("Failed at {path:?}: {message}"))
                }
                ErrorKind::MissingElement => {
                    UseIdError::GenericError(format!("Missing element: {message}"))
                }
                ErrorKind::InvalidElement => {
                    UseIdError::GenericError(format!("Invalid element at {path:?}: {message}"))
                }
                ErrorKind::Serialization => UseIdError::GenericError(message),
            },
        }
    }
}
