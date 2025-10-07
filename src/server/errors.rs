use std::fmt;
use thiserror::Error;
use validator::ValidationErrors;

use crate::domain::models::ResultType;

const SOAP_MINOR_PREFIX: &str = "http://www.bsi.bund.de/eid/server/2.0/resultminor/";
const PAOS_MINOR_PREFIX: &str = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/";
const INVALID_REQUEST: &str = "al/common#unknownAPIFunction";

// eID interface errors
mod soap {
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

// eCard-API-Framework interface errors
mod paos {
    pub const NO_PERMISSION: &str = "al/common#noPermission";
    pub const INTERNAL_ERROR: &str = "al/common#internalError";
    pub const PARAMETER_ERROR: &str = "al/common#parameterError";
    pub const NODE_NOT_REACHABLE: &str = "dp#nodeNotReachable";
    pub const TIMEOUT: &str = "dp#timeout";
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("API function not supported")]
    InvalidRequest,
    #[error(transparent)]
    Eid(EidError),
    #[error(transparent)]
    Paos(PaosError),
}

impl AppError {
    /// Convenience function to create a SOAP internal error
    pub fn soap_internal<E: fmt::Debug>(e: E) -> Self {
        tracing::error!("Service failure: {e:?}");
        AppError::Eid(EidError::Internal)
    }

    /// Convenience function to create a PAOS internal error
    pub fn paos_internal<E: fmt::Debug>(e: E) -> Self {
        tracing::error!("Service failure: {e:?}");
        AppError::Paos(PaosError::Internal)
    }

    /// Convert this error to a ResultType
    pub fn to_result(&self) -> ResultType {
        let error_code = match self {
            AppError::InvalidRequest => INVALID_REQUEST.into(),
            AppError::Eid(eid_error) => eid_error.to_error_code(),
            AppError::Paos(paos_error) => paos_error.to_error_code(),
        };
        ResultType::error(&error_code, Some(&self.to_string()))
    }
}

impl From<quick_xml::DeError> for AppError {
    fn from(_: quick_xml::DeError) -> Self {
        AppError::InvalidRequest
    }
}

/// Error type for eID operations
#[derive(Error, Debug)]
#[allow(unused)]
pub enum EidError {
    #[error("The service has encountered an unexpected internal state")]
    Internal,
    #[error("{0}")]
    SchemaViolation(String),
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

impl From<ValidationErrors> for EidError {
    fn from(error: ValidationErrors) -> Self {
        EidError::SchemaViolation(error.to_string())
    }
}

impl EidError {
    /// Convert this error to a error code
    pub fn to_error_code(&self) -> String {
        use EidError::*;

        match self {
            Internal => soap_error_code(soap::INTERNAL_ERROR),
            SchemaViolation(_) => soap_error_code(soap::SCHEMA_VIOLATION),
            InvalidPSK => soap_error_code(soap::INVALID_PSK),
            TooManyOpenSessions => soap_error_code(soap::TOO_MANY_OPEN_SESSIONS),
            MissingArgument(_) => soap_error_code(soap::MISSING_ARGUMENT),
            MissingTerminalRights => soap_error_code(soap::MISSING_TERMINAL_RIGHTS),
            NoResultYet => soap_error_code(soap::NO_RESULT_YET),
            InvalidSession => soap_error_code(soap::INVALID_SESSION),
            InvalidCounter => soap_error_code(soap::INVALID_COUNTER),
            DeniedDocument => soap_error_code(soap::DENIED_DOCUMENT),
            InvalidDocument(_) => soap_error_code(soap::INVALID_DOCUMENT),
        }
    }
}

impl From<EidError> for AppError {
    fn from(error: EidError) -> Self {
        AppError::Eid(error)
    }
}

#[derive(Error, Debug)]
#[allow(unused)]
pub enum PaosError {
    #[error("The service has encountered an unexpected internal state")]
    Internal,
    #[error("{0}")]
    Parameter(String),
    #[error("Missing permissions")]
    MissingPermissions,
    #[error("Node not reachable")]
    NodeNotReachable,
    #[error("The authentication process has timed out")]
    Timeout,
}

impl PaosError {
    /// Convert this error to a error code
    pub fn to_error_code(&self) -> String {
        use PaosError::*;

        match self {
            Internal => paos_error_code(paos::INTERNAL_ERROR),
            Parameter(_) => paos_error_code(paos::PARAMETER_ERROR),
            MissingPermissions => paos_error_code(paos::NO_PERMISSION),
            NodeNotReachable => paos_error_code(paos::NODE_NOT_REACHABLE),
            Timeout => paos_error_code(paos::TIMEOUT),
        }
    }
}

impl From<PaosError> for AppError {
    fn from(error: PaosError) -> Self {
        AppError::Paos(error)
    }
}

impl From<ValidationErrors> for PaosError {
    fn from(error: ValidationErrors) -> Self {
        PaosError::Parameter(error.to_string())
    }
}

macro_rules! impl_paos_internal_error {
    ($($error_type:ty),* $(,)?) => {
        $(
            impl From<$error_type> for AppError {
                fn from(error: $error_type) -> Self {
                    AppError::paos_internal(error)
                }
            }
        )*
    };
}
pub(crate) use impl_paos_internal_error;

impl_paos_internal_error! {
    crate::session::SessionError,
    crate::pki::identity::Error,
}

#[inline]
fn soap_error_code(suffix: &str) -> String {
    format!("{SOAP_MINOR_PREFIX}{suffix}")
}

#[inline]
fn paos_error_code(suffix: &str) -> String {
    format!("{PAOS_MINOR_PREFIX}{suffix}")
}
