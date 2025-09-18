use std::fmt;
use thiserror::Error;
use validator::ValidationErrors;

use crate::domain::models::ResultType;

pub(super) mod error_codes {
    pub const INTERNAL_ERROR: &str = "common#internalError";
    pub const SCHEMA_VIOLATION: &str = "common#schemaViolation";
    pub const INVALID_PSK: &str = "useID#invalidPSK";
    pub const TOO_MANY_OPEN_SESSIONS: &str = "useID#tooManyOpenSessions";
    pub const MISSING_ARGUMENT: &str = "useID#missingArgument";
    pub const MISSING_TERMINAL_RIGHTS: &str = "useID#missingTerminalRights";
    pub const NO_RESULT_YET: &str = "getResult#noResultYet";
    pub const INVALID_SESSION: &str = "getResult#invalidSession";
    pub const INVALID_COUNTER: &str = "getResult#invalidCounter";
    pub const DENIED_DOCUMENT: &str = "getResult#deniedDocument";
    pub const INVALID_DOCUMENT: &str = "getResult#invalidDocument";
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("The service has encountered an unexpected internal state")]
    Internal,
    #[error("Schema violation: {0}")]
    SchemaViolation(String),
    #[error(transparent)]
    Eid(EidError),
}

impl AppError {
    /// Convenience function to create an internal error
    pub fn internal<E: fmt::Debug>(e: E) -> Self {
        tracing::error!("Service failure: {e:?}");
        AppError::Internal
    }

    /// Convert this error to a ResultType
    pub fn to_result(&self) -> ResultType {
        let minor = match self {
            AppError::Internal => error_codes::INTERNAL_ERROR,
            AppError::SchemaViolation(_) => error_codes::SCHEMA_VIOLATION,
            AppError::Eid(eid_error) => eid_error.to_minor(),
        };
        ResultType::error(minor, Some(&self.to_string()))
    }
}

impl From<ValidationErrors> for AppError {
    fn from(error: ValidationErrors) -> Self {
        AppError::SchemaViolation(error.to_string())
    }
}

impl From<quick_xml::DeError> for AppError {
    fn from(error: quick_xml::DeError) -> Self {
        AppError::SchemaViolation(error.to_string())
    }
}

/// Error type for eID operations
#[derive(Error, Debug)]
#[allow(unused)]
pub enum EidError {
    #[error("The PreSharedKey is invalid")]
    InvalidPSK,
    #[error("The maximum number of open sessions has been reached")]
    TooManyOpenSessions,
    #[error(
        "The function {0} has been selected but \
        the corresponding request element is missing"
    )]
    MissingArgument(String),
    #[error("The necessary permissions are missing")]
    MissingTerminalRights,
    #[error("The result is not yet available")]
    NoResultYet,
    #[error("The session is invalid or has expired")]
    InvalidSession,
    #[error("Invalid request counter")]
    InvalidCounter,
    #[error("eID-Document did not match level of assurance or has been denied")]
    DeniedDocument,
    #[error("Invalid eID-Document: {0}")]
    InvalidDocument(String),
}

impl EidError {
    /// Convert the error to a minor code
    pub fn to_minor(&self) -> &'static str {
        use EidError::*;

        match self {
            InvalidPSK => error_codes::INVALID_PSK,
            TooManyOpenSessions => error_codes::TOO_MANY_OPEN_SESSIONS,
            MissingArgument(_) => error_codes::MISSING_ARGUMENT,
            MissingTerminalRights => error_codes::MISSING_TERMINAL_RIGHTS,
            NoResultYet => error_codes::NO_RESULT_YET,
            InvalidSession => error_codes::INVALID_SESSION,
            InvalidCounter => error_codes::INVALID_COUNTER,
            DeniedDocument => error_codes::DENIED_DOCUMENT,
            InvalidDocument(_) => error_codes::INVALID_DOCUMENT,
        }
    }
}

impl From<EidError> for AppError {
    fn from(error: EidError) -> Self {
        AppError::Eid(error)
    }
}
