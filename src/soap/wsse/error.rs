use color_eyre::eyre::Report;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XML processing error: {0}")]
    Xml(#[from] Report),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::Error),

    #[error("X509 parsing error: {0}")]
    X509Parse(#[from] x509_parser::error::X509Error),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] crate::pki::truststore::TrustStoreError),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Invalid data: {0}")]
    Invalid(String),

    #[error("{0}")]
    Other(String),
}

impl From<quick_xml::Error> for Error {
    fn from(err: quick_xml::Error) -> Self {
        Error::Xml(err.into())
    }
}

impl From<quick_xml::DeError> for Error {
    fn from(err: quick_xml::DeError) -> Self {
        Error::Xml(err.into())
    }
}

impl From<quick_xml::SeError> for Error {
    fn from(err: quick_xml::SeError) -> Self {
        Error::Xml(err.into())
    }
}

impl From<quick_xml::events::attributes::AttrError> for Error {
    fn from(err: quick_xml::events::attributes::AttrError) -> Self {
        Error::Xml(err.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Xml(err.into())
    }
}

impl From<time::error::Format> for Error {
    fn from(err: time::error::Format) -> Self {
        Error::Other(err.to_string())
    }
}

impl From<time::error::Parse> for Error {
    fn from(err: time::error::Parse) -> Self {
        Error::Other(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Utf8(err.utf8_error())
    }
}
