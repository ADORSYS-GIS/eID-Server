use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum UseIdError {
    #[error("invalid PSK")]
    InvalidPSK,
    #[error("Maximum number of sessions is reached: server overloaded")]
    TooManyOpenSessions,
    #[error("Parameters are missing: {0}")]
    MissingArguments(String),
    #[error(
        "Necessary Permissions are missing: permissions missing in terminal authorization certificate"
    )]
    MissingTerminalRights,
    #[error("Request still has not been completed")]
    NoResultYet,
    #[error("error: {0}")]
    GenericError(String),
}

impl From<quick_xml::Error> for UseIdError {
    fn from(value: quick_xml::Error) -> Self {
        Self::GenericError(format!("{value}"))
    }
}
