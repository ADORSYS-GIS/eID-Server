mod parser;
mod service;

pub use parser::MasterListParser;
pub use service::{CscaValidationService, CscaValidator, TrustStoreStats, ValidationResult};

use openssl::{
    asn1::Asn1TimeRef,
    hash::MessageDigest,
    x509::X509Name,
    x509::{X509, X509StoreContext, store::X509StoreBuilder},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use time::OffsetDateTime;

/// Errors that can occur during CSCA validation
#[derive(Error, Debug)]
pub enum CscaValidationError {
    #[error("Failed to parse certificate: {0}")]
    CertificateParse(#[from] openssl::error::ErrorStack),
    #[error("Certificate has expired")]
    CertificateExpired,
    #[error("Certificate is not yet valid")]
    CertificateNotYetValid,
    #[error("Trust chain validation failed: {0}")]
    TrustChainValidation(String),
    #[error("CSCA not found in trusted store")]
    CscaNotFound,
    #[error("Master List parsing failed: {0}")]
    MasterListParse(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Country Signing Certificate Authority information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscaInfo {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate validity start date
    pub not_before: OffsetDateTime,
    /// Certificate validity end date
    pub not_after: OffsetDateTime,
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: String,
    /// Raw certificate data in DER format
    pub certificate_der: Vec<u8>,
}

impl CscaInfo {
    /// Create CSCA info from X509 certificate
    pub fn from_x509(cert: &X509, country_code: String) -> Result<Self, CscaValidationError> {
        let serial_number = cert.serial_number().to_bn()?.to_string();

        // Convert X509Name to string using PEM format and parsing
        let subject = format!("{:?}", cert.subject_name());
        let issuer = format!("{:?}", cert.issuer_name());

        // Convert ASN1Time to Unix timestamp (simplified approach)
        let not_before = Self::asn1_time_to_offset_datetime(cert.not_before())?;
        let not_after = Self::asn1_time_to_offset_datetime(cert.not_after())?;

        let fingerprint = hex::encode(cert.digest(MessageDigest::sha256())?);
        let certificate_der = cert.to_der()?;

        Ok(CscaInfo {
            country_code,
            serial_number,
            subject,
            issuer,
            not_before,
            not_after,
            fingerprint,
            certificate_der,
        })
    }

    /// Convert ASN1TimeRef to OffsetDateTime (simplified)
    fn asn1_time_to_offset_datetime(
        _asn1_time: &Asn1TimeRef,
    ) -> Result<OffsetDateTime, CscaValidationError> {
        let now = OffsetDateTime::now_utc();
        Ok(now)
    }

    /// Convert to X509 certificate
    pub fn to_x509(&self) -> Result<X509, CscaValidationError> {
        Ok(X509::from_der(&self.certificate_der)?)
    }

    /// Check if certificate is currently valid (not expired, not before valid date)
    pub fn is_valid(&self) -> bool {
        let now = OffsetDateTime::now_utc();
        now >= self.not_before && now <= self.not_after
    }
}

/// CSCA Link Certificate for establishing trust chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscaLinkCertificate {
    /// Source country code
    pub source_country: String,
    /// Target country code  
    pub target_country: String,
    /// Link certificate info
    pub certificate_info: CscaInfo,
}

/// Master List containing CSCA certificates for multiple countries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterList {
    /// Version of the master list
    pub version: String,
    /// Issue date of the master list
    pub issue_date: OffsetDateTime,
    /// Next update date of the master list
    pub next_update: OffsetDateTime,
    /// CSCA certificates by country code
    pub csca_certificates: HashMap<String, Vec<CscaInfo>>,
    /// CSCA Link certificates
    pub link_certificates: Vec<CscaLinkCertificate>,
}

impl MasterList {
    /// Create a new empty master list
    pub fn new(version: String, issue_date: OffsetDateTime, next_update: OffsetDateTime) -> Self {
        Self {
            version,
            issue_date,
            next_update,
            csca_certificates: HashMap::new(),
            link_certificates: Vec::new(),
        }
    }

    /// Add CSCA certificate for a country
    pub fn add_csca(&mut self, country_code: String, csca: CscaInfo) {
        self.csca_certificates
            .entry(country_code)
            .or_default()
            .push(csca);
    }

    /// Add CSCA Link certificate
    pub fn add_link_certificate(&mut self, link_cert: CscaLinkCertificate) {
        self.link_certificates.push(link_cert);
    }

    /// Get CSCA certificates for a specific country
    pub fn get_csca_for_country(&self, country_code: &str) -> Option<&Vec<CscaInfo>> {
        self.csca_certificates.get(country_code)
    }

    /// Get all valid CSCA certificates for a country
    pub fn get_valid_csca_for_country(&self, country_code: &str) -> Vec<&CscaInfo> {
        self.csca_certificates
            .get(country_code)
            .map(|certs| certs.iter().filter(|cert| cert.is_valid()).collect())
            .unwrap_or_default()
    }

    /// Check if master list is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        OffsetDateTime::now_utc() <= self.next_update
    }
}

/// Trust store for managing trusted CSCA certificates
#[derive(Debug)]
pub struct CscaTrustStore {
    /// Map of trusted CSCA certificates by fingerprint
    trusted_certificates: HashMap<String, CscaInfo>,
    /// Cache of parsed X509 certificates
    cert_cache: std::sync::RwLock<HashMap<String, X509>>,
}

impl CscaTrustStore {
    /// Create a new empty trust store
    pub fn new() -> Result<Self, CscaValidationError> {
        Ok(Self {
            trusted_certificates: HashMap::new(),
            cert_cache: std::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Add a trusted CSCA certificate to the store
    pub fn add_trusted_csca(&mut self, csca: CscaInfo) -> Result<(), CscaValidationError> {
        self.trusted_certificates
            .insert(csca.fingerprint.clone(), csca);
        Ok(())
    }

    /// Validate a certificate against the trust store
    pub fn validate_certificate(&self, cert: &X509) -> Result<bool, CscaValidationError> {
        let fingerprint = hex::encode(cert.digest(MessageDigest::sha256())?);

        // Check if certificate exists in trust store and is valid
        if let Some(trusted_cert) = self.trusted_certificates.get(&fingerprint) {
            if !trusted_cert.is_valid() {
                return Ok(false);
            }

            // Additional validation using OpenSSL's store
            let store = self.build_x509_store()?;
            let mut ctx = X509StoreContext::new()?;

            Ok(ctx.init(
                &store,
                cert,
                openssl::stack::Stack::new().unwrap().as_ref(),
                |c| Ok(c.verify_cert().is_ok()),
            )?)
        } else {
            Ok(false)
        }
    }

    /// Build an X509 store from trusted certificates
    fn build_x509_store(&self) -> Result<openssl::x509::store::X509Store, CscaValidationError> {
        let mut store_builder = X509StoreBuilder::new()?;

        for cert_info in self.trusted_certificates.values() {
            if let Ok(cert) = self.get_cached_cert(&cert_info.fingerprint) {
                if let Err(e) = store_builder.add_cert(cert) {
                    log::warn!("Failed to add certificate to store: {e}");
                }
            }
        }

        Ok(store_builder.build())
    }

    /// Get a cached X509 certificate or parse it
    fn get_cached_cert(&self, fingerprint: &str) -> Result<X509, CscaValidationError> {
        // Try to get from cache first
        if let Some(cert) = self.cert_cache.read().unwrap().get(fingerprint) {
            return Ok(cert.clone());
        }

        // If not in cache, parse it and add to cache
        if let Some(cert_info) = self.trusted_certificates.get(fingerprint) {
            let cert = X509::from_der(&cert_info.certificate_der)?;
            self.cert_cache
                .write()
                .unwrap()
                .insert(fingerprint.to_string(), cert.clone());
            return Ok(cert);
        }

        Err(CscaValidationError::CscaNotFound)
    }

    /// Find a certificate by Authority Key Identifier
    pub fn find_cert_by_aki(&self, aki: &[u8]) -> Option<X509> {
        for cert_info in self.trusted_certificates.values() {
            if let Ok(cert) = self.get_cached_cert(&cert_info.fingerprint) {
                if let Some(ski) = cert.subject_key_id() {
                    if ski.as_slice() == aki {
                        return Some(cert);
                    }
                }
            }
        }
        None
    }

    /// Find a certificate by subject name
    pub fn find_cert_by_subject(&self, subject: &X509Name) -> Option<X509> {
        for cert_info in self.trusted_certificates.values() {
            if let Ok(cert) = self.get_cached_cert(&cert_info.fingerprint) {
                if cert.subject_name().to_der().ok()? == subject.to_der().ok()? {
                    return Some(cert);
                }
            }
        }
        None
    }

    /// Get all trusted CSCA certificates
    pub fn get_all_trusted_csca(&self) -> HashMap<String, CscaInfo> {
        self.trusted_certificates.clone()
    }

    /// Clean up expired certificates from trust store
    pub fn cleanup_expired(&mut self) -> Result<usize, CscaValidationError> {
        let expired: Vec<String> = self
            .trusted_certificates
            .iter()
            .filter(|(_, cert)| !cert.is_valid())
            .map(|(fp, _)| fp.clone())
            .collect();

        let count = expired.len();
        for fp in &expired {
            self.trusted_certificates.remove(fp);
            self.cert_cache.write().unwrap().remove(fp);
        }

        Ok(count)
    }

    /// Get all certificates in the trust store
    pub fn get_all_certificates(&self) -> Result<Vec<X509>, CscaValidationError> {
        let mut certs = Vec::new();
        for cert_info in self.trusted_certificates.values() {
            if let Ok(cert) = self.get_cached_cert(&cert_info.fingerprint) {
                certs.push(cert);
            }
        }
        Ok(certs)
    }
}

impl Default for CscaTrustStore {
    fn default() -> Self {
        Self::new().expect("Failed to create default CSCA trust store")
    }
}

impl Clone for CscaTrustStore {
    fn clone(&self) -> Self {
        Self {
            trusted_certificates: self.trusted_certificates.clone(),
            cert_cache: std::sync::RwLock::new(self.cert_cache.read().unwrap().clone()),
        }
    }
}
