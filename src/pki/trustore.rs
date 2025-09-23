use async_trait::async_trait;
use color_eyre::eyre::Report;
use openssl::error::ErrorStack;
use openssl::x509::{X509, X509NameRef};
use thiserror::Error;

/// Error type for trust store operations.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] ErrorStack),

    #[error(transparent)]
    Custom(#[from] Report),
}

/// Represents a certificate with additional metadata.
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub raw: Vec<u8>,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
}

impl CertificateEntry {
    pub fn from_der(der: impl AsRef<[u8]>) -> Result<Self, TrustStoreError> {
        let cert = X509::from_der(der.as_ref())?;
        let serial_number = Self::extract_serial_number(&cert)?;
        let subject = Self::format_name(cert.subject_name());
        let issuer = Self::format_name(cert.issuer_name());
        Ok(Self {
            raw: der.as_ref().to_vec(),
            serial_number,
            subject,
            issuer,
        })
    }

    fn extract_serial_number(cert: &X509) -> Result<String, TrustStoreError> {
        let serial = cert.serial_number();
        let serial_bn = serial.to_bn()?;
        Ok(serial_bn.to_hex_str()?.to_string())
    }

    fn format_name(name: &X509NameRef) -> String {
        name.entries()
            .map(|entry| {
                format!(
                    "{}={}",
                    entry.object().nid().short_name().unwrap_or_default(),
                    match entry.data().as_utf8() {
                        Ok(d) => d.to_string(),
                        Err(_) => String::new(),
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Abstract interface for a trust store.
#[async_trait]
pub trait TrustStore: Send + Sync + 'static {
    /// Add DER encoded certificates to the trust store.
    ///
    /// Returns the number of certificates added.
    async fn add_certs(
        &self,
        der_certs: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<usize, TrustStoreError>;

    /// Get a certificate by its serial number.
    async fn get_cert_by_serial(
        &self,
        serial_number: &str,
    ) -> Result<Option<CertificateEntry>, TrustStoreError>;

    /// Get a certificate by its subject DN.
    async fn get_cert_by_subject(
        &self,
        subject: &str,
    ) -> Result<Option<CertificateEntry>, TrustStoreError>;

    /// Verify the given DER encoded certificate chain against the trust store.
    ///
    /// The first element of the chain must be the end entity certificate.
    async fn verify(
        &self,
        der_chain: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<(), TrustStoreError>;

    /// Remove a certificate from the trust store by its serial number.
    async fn remove_cert(&self, serial_number: &str) -> Result<bool, TrustStoreError>;

    /// Remove all certificates from the trust store.
    async fn clear(&self) -> Result<(), TrustStoreError>;
}
