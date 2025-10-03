//! Certificate Revocation List (CRL) implementation
//!
//! This module provides comprehensive CRL support according to ICAO 9303-12 §6.2
//!
//! # Features
//! - CRL fetching from distribution points
//! - CRL validation (signature, timing, issuer authorization)
//! - Certificate revocation checking
//! - Revocation reason extraction
//! - Parallel CRL fetching
//! - CRL caching

mod errors;
mod fetcher;
mod manager;
mod parser;
mod types;
mod validation;

// Re-export public types
pub use errors::{CrlError, CrlResult};
pub use manager::CrlManager;
pub use types::{CrlEntry, RevocationInfo, RevocationReason};

// Re-export validation functions for convenience
pub use validation::{validate_crl_signature, validate_crl_timing};
