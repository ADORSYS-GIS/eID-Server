//! Certificate Revocation List (CRL) implementation
//!
//! This module provides CRL support according to ICAO 9303-12 §6.2
//!
//! # Features
//! - CRL fetching from configured distribution points
//! - Parsing CRL to extract revoked certificate serial numbers
//! - Removing revoked certificates from trust store
//! - Scheduled periodic CRL checking

mod errors;
mod processor;
pub mod scheduler;
mod types;

// Re-export public types
pub use errors::{CrlError, CrlResult};
pub use processor::CrlProcessor;
pub use scheduler::{CrlScheduler, CrlSchedulerConfig};
pub use types::CrlData;
