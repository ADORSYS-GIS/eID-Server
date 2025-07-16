use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoapError {
    #[error("XML serialization failed: {0}")]
    SerializationError(String),
    #[error("XML deserialization failed at {path}: {message}")]
    DeserializationError { path: String, message: String },
    #[error("Missing required element: {0}")]
    MissingElement(String),
    #[error("Invalid element value at {path}: {message}")]
    InvalidElement { path: String, message: String },
}
