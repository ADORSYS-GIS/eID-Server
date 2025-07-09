//! Ports (interfaces) for the transmit domain.
//! These define the contracts that external modules use to interact with the transmit domain.

use async_trait::async_trait;

/// Result type for transmit operations
pub type TransmitResult<T> = Result<T, TransmitError>;

/// Errors that can occur during transmit operations
#[derive(Debug, thiserror::Error)]
pub enum TransmitError {
    #[error("APDU transmission failed: {0}")]
    TransmissionFailed(String),

    #[error("Invalid APDU format: {0}")]
    InvalidApdu(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),
}

/// Service interface for APDU transmission
/// This abstracts the external dependencies and provides a clean domain interface
#[async_trait]
pub trait TransmitService: Send + Sync {
    /// Transmits an APDU to the eID-Client and returns the response
    ///
    /// # Arguments
    /// * `apdu` - The APDU bytes to transmit
    /// * `slot_handle` - The slot handle for the session
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The response APDU bytes
    /// * `Err(TransmitError)` - If transmission fails
    async fn transmit_apdu(&self, apdu: Vec<u8>, slot_handle: &str) -> TransmitResult<Vec<u8>>;
}
