use thiserror::Error;

#[derive(Debug, Error)]
pub enum UseIdError {
    #[error("error: {0}")]
    GenericError(String),
}

impl From<quick_xml::Error> for UseIdError {
    fn from(value: quick_xml::Error) -> Self {
        Self::GenericError(format!("{value}"))
    }
}
