pub mod constants;
pub mod signer;
pub mod types;
pub mod utils;
pub mod validator;

// Re-export public APIs for backward compatibility
pub use signer::XmlSignatureSigner;
pub use types::{SignatureAlgorithm, ValidationResult};
pub use validator::XmlSignatureValidator;
