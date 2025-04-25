use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommonError{
    #[error("internal server error")]
    InternalServerError,
    #[error("invalid schema")]
    SechemaViolation,
}