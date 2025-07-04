use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransmitError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Invalid APDU status code: expected {expected}, got {actual}")]
    InvalidStatusCode { expected: String, actual: String },

    #[error("Card communication error: {0}")]
    CardError(String),

    #[error("Invalid PSK: {0}")]
    InvalidPSK(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<quick_xml::Error> for TransmitError {
    fn from(err: quick_xml::Error) -> Self {
        TransmitError::ProtocolError(format!("XML error: {}", err))
    }
}

impl From<std::io::Error> for TransmitError {
    fn from(err: std::io::Error) -> Self {
        TransmitError::InternalError(format!("IO error: {}", err))
    }
}

impl From<std::str::Utf8Error> for TransmitError {
    fn from(err: std::str::Utf8Error) -> Self {
        TransmitError::InvalidRequest(format!("Invalid UTF-8 in request: {}", err))
    }
}
