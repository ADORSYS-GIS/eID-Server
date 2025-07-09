use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransmitError {
    #[error("Transmit error: {0}")]
    TransmitError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<quick_xml::Error> for TransmitError {
    fn from(err: quick_xml::Error) -> Self {
        TransmitError::TransmitError(format!("XML error: {}", err))
    }
}

impl From<std::io::Error> for TransmitError {
    fn from(err: std::io::Error) -> Self {
        TransmitError::InternalError(format!("IO error: {}", err))
    }
}

impl From<std::str::Utf8Error> for TransmitError {
    fn from(err: std::str::Utf8Error) -> Self {
        TransmitError::TransmitError(format!("Invalid UTF-8 in request: {}", err))
    }
}
