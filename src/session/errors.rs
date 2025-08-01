use crate::session::store::SessionStoreError;

/// Session errors.
#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    Store(#[from] SessionStoreError),

    #[error(transparent)]
    Bincode(#[from] bincode::error::EncodeError),

    #[error(transparent)]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("Maximum number of sessions reached")]
    MaxSessions,
}
