use crate::session::store::SessionStoreError;
use color_eyre::Report;

/// Session errors.
#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    Store(#[from] SessionStoreError),

    #[error(transparent)]
    Encode(#[from] bincode::error::EncodeError),

    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Maximum number of sessions reached")]
    MaxSessions,

    #[error(transparent)]
    Other(#[from] Report),
}
