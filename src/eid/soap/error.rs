use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoapError {
    #[error("{kind} at {path:?}: {message}")]
    XmlError {
        kind: ErrorKind,
        path: Option<String>,
        message: String,
    },
}

#[derive(Debug)]
pub enum ErrorKind {
    Serialization,
    Deserialization,
    MissingElement,
    InvalidElement,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Serialization => write!(f, "XML serialization failed"),
            ErrorKind::Deserialization => write!(f, "XML deserialization failed"),
            ErrorKind::MissingElement => write!(f, "Missing required element"),
            ErrorKind::InvalidElement => write!(f, "Invalid element value"),
        }
    }
}
