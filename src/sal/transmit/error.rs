#[derive(Debug, thiserror::Error)]
pub enum TransmitError {
    #[error("APDU transmission failed: {0}")]
    TransmissionFailed(String),
    #[error("Invalid APDU format")]
    InvalidApdu,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
} 