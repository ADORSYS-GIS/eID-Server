#[derive(Debug, thiserror::Error)]
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
