use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use color_eyre::eyre::{Report, eyre};
use dashmap::DashMap;
use thiserror::Error;
use tokio::fs;
use walkdir::WalkDir;
use x509_parser::prelude::*;

/// Error type for trust store operations.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("X.509 error: {0}")]
    X509(#[from] X509Error),

    #[error(transparent)]
    Custom(#[from] Report),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<walkdir::Error> for TrustStoreError {
    fn from(e: walkdir::Error) -> Self {
        TrustStoreError::Io(e.into())
    }
}

/// Represents a certificate with additional metadata.
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub raw: Arc<Vec<u8>>,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
}

impl CertificateEntry {
    /// Create a certificate entry from DER-encoded bytes
    pub fn from_der(der: impl AsRef<[u8]>) -> Result<Self, TrustStoreError> {
        let der_bytes = der.as_ref();
        let (_, cert) =
            X509Certificate::from_der(der_bytes).map_err(|e| TrustStoreError::X509(e.into()))?;

        let serial_number = cert.tbs_certificate.serial.to_string();
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        Ok(Self {
            raw: Arc::new(der_bytes.to_vec()),
            serial_number,
            subject,
            issuer,
        })
    }

    /// Parse the certificate from stored DER bytes
    pub fn parse(&self) -> Result<X509Certificate<'_>, TrustStoreError> {
        let (_, cert) =
            X509Certificate::from_der(&self.raw).map_err(|e| TrustStoreError::X509(e.into()))?;
        Ok(cert)
    }
}

/// Abstract interface for a trust store.
pub trait TrustStore: Clone + Send + Sync + 'static {
    /// Add DER encoded certificates to the trust store.
    ///
    /// Returns the number of certificates added.
    fn add_certs<I, D>(
        &self,
        der_certs: I,
    ) -> impl Future<Output = Result<usize, TrustStoreError>> + Send
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send;

    /// Get a certificate by its serial number.
    fn get_cert_by_serial(
        &self,
        serial_number: &str,
    ) -> impl Future<Output = Result<Option<CertificateEntry>, TrustStoreError>> + Send;

    /// Get a certificate by its subject DN.
    fn get_cert_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<CertificateEntry>, TrustStoreError>> + Send;

    /// Verify the given DER encoded certificate chain against the trust store.
    /// The first element of the chain must be the leaf certificate.
    ///
    /// Verification succeeds if a valid path can be built from the leaf
    /// certificate to a trusted root certificate in the trust store.
    ///
    /// An error will be returned if the certificate is invalid (e.g. expired).
    /// If the chain contains more than 10 certificates, an error will be returned.
    fn verify<I, D>(
        &self,
        der_chain: I,
    ) -> impl Future<Output = Result<bool, TrustStoreError>> + Send
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send;

    /// Remove a certificate from the trust store by its serial number.
    fn remove_cert(
        &self,
        serial_number: &str,
    ) -> impl Future<Output = Result<bool, TrustStoreError>> + Send;

    /// Remove all certificates from the trust store.
    fn clear(&self) -> impl Future<Output = Result<(), TrustStoreError>> + Send;

    /// Get all certificates from the trust store for iteration.
    fn iter_all_certificates(
        &self,
    ) -> impl Future<Output = Result<Vec<CertificateEntry>, TrustStoreError>> + Send;
}

/// In-memory trust store implementation.
///
/// All added certificates are stored in memory and not persisted to disk.
/// It is assumed that the certificates are loaded from a directory.
///
/// Useful for development and testing.
#[derive(Debug, Clone)]
pub struct MemoryTrustStore {
    base_path: PathBuf,
    cache: Arc<DashMap<String, CertificateEntry>>,
}

impl MemoryTrustStore {
    /// Create a new in-memory trust store.
    ///
    /// Loads a list of known certificates from the specified directory.
    /// Make sure the directory contains only valid certificates with .der, .pem, or .crt extensions.
    pub async fn new<P: Into<PathBuf>>(base_path: P) -> Result<Self, TrustStoreError> {
        let store = Self {
            base_path: base_path.into(),
            cache: Arc::new(DashMap::new()),
        };

        store.load_from_disk().await?;
        Ok(store)
    }

    /// Return the amount of certificates currently cached.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the trust store is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Produce an iterator over all stored certificates.
    pub fn iter(&self) -> impl Iterator<Item = CertificateEntry> + '_ {
        self.cache.iter().map(|e| e.value().clone())
    }

    async fn load_from_disk(&self) -> Result<(), TrustStoreError> {
        let mut count = 0;

        for entry in WalkDir::new(&self.base_path) {
            let entry = entry?;
            let path = entry.path();

            if path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("der")
                        || ext.eq_ignore_ascii_case("pem")
                        || ext.eq_ignore_ascii_case("crt")
                })
                && let Ok(der_bytes) = fs::read(path).await
                && let Ok(cert_entry) = CertificateEntry::from_der(der_bytes)
            {
                self.cache
                    .insert(cert_entry.serial_number.clone(), cert_entry);
                count += 1;
            }
        }
        tracing::info!("Loaded {count} certificates from disk");
        Ok(())
    }

    // Try to find an issuer certificate for the given certificate
    fn find_issuer_cert(
        &self,
        cert: &X509Certificate<'_>,
        chain_pool: &[CertificateEntry],
    ) -> Option<CertificateEntry> {
        let issuer_dn = cert.issuer();
        // First, we look in the provided chain
        for entry in chain_pool {
            if let Ok(candidate) = entry.parse()
                && candidate.subject() == issuer_dn
            {
                // Verify the signature to ensure this is the correct issuer
                if cert.verify_signature(Some(candidate.public_key())).is_ok() {
                    return Some(entry.clone());
                }
            }
        }
        // If not found, we look in the trust store
        for entry in self.cache.iter() {
            if let Ok(candidate) = entry.value().parse()
                && candidate.subject() == issuer_dn
            {
                // Verify the signature to ensure this is the correct issuer
                if cert.verify_signature(Some(candidate.public_key())).is_ok() {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    // Check if a certificate is trusted
    fn is_trusted_root(&self, cert: &X509Certificate<'_>) -> bool {
        self.cache.iter().any(|entry| {
            if let Ok(trusted_cert) = entry.value().parse() {
                trusted_cert.subject() == cert.subject()
                    && trusted_cert.public_key().raw == cert.public_key().raw
                    && trusted_cert.verify_signature(None).is_ok()
            } else {
                false
            }
        })
    }

    // Try to build a certificate chain up to a trusted root
    fn build_chain(
        &self,
        chain_certs: Vec<CertificateEntry>,
    ) -> Result<Vec<CertificateEntry>, TrustStoreError> {
        if chain_certs.is_empty() {
            return Err(TrustStoreError::Custom(eyre!("Empty certificate chain")));
        }

        let mut built_chain = Vec::new();
        let mut current_entry = chain_certs[0].clone();
        let mut used_serials = HashSet::new();

        loop {
            let current_cert = current_entry.parse()?;

            if used_serials.contains(&current_entry.serial_number) {
                return Err(TrustStoreError::Custom(eyre!(
                    "Certificate chain contains a cycle"
                )));
            }
            used_serials.insert(current_entry.serial_number.clone());
            built_chain.push(current_entry.clone());

            // Check if we've reached a trusted root
            if self.is_trusted_root(&current_cert) {
                return Ok(built_chain);
            }

            if current_cert.subject() == current_cert.issuer() {
                return Err(TrustStoreError::Custom(eyre!(
                    "Self-signed certificate not in trust store"
                )));
            }

            match self.find_issuer_cert(&current_cert, &chain_certs) {
                Some(issuer_entry) => {
                    current_entry = issuer_entry;
                }
                None => {
                    return Err(TrustStoreError::Custom(eyre!(
                        "Cannot find issuer for certificate: {}",
                        current_cert.subject()
                    )));
                }
            }
        }
    }

    /// Verify a certificate chain by checking signatures and validity
    fn verify_chain(&self, chain: &[CertificateEntry]) -> Result<bool, TrustStoreError> {
        for i in 0..chain.len() {
            let cert = chain[i].parse()?;

            if !cert.validity().is_valid() {
                return Ok(false);
            }

            if i == chain.len() - 1 {
                // Root certificate. Should be self-signed and trusted
                if cert.subject() != cert.issuer() {
                    return Ok(false);
                }
                if cert.verify_signature(None).is_err() {
                    return Ok(false);
                }
                if !self.is_trusted_root(&cert) {
                    return Ok(false);
                }
            } else {
                // Verify signature using the next certificate in chain
                let issuer_cert = chain[i + 1].parse()?;
                if cert
                    .verify_signature(Some(issuer_cert.public_key()))
                    .is_err()
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl TrustStore for MemoryTrustStore {
    async fn add_certs<I, D>(&self, der_certs: I) -> Result<usize, TrustStoreError>
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send,
    {
        let mut count = 0;
        for der_cert in der_certs {
            if let Ok(cert_entry) = CertificateEntry::from_der(der_cert.as_ref()) {
                self.cache
                    .insert(cert_entry.serial_number.clone(), cert_entry);
                count += 1;
            }
        }
        Ok(count)
    }

    async fn get_cert_by_serial(
        &self,
        serial_number: &str,
    ) -> Result<Option<CertificateEntry>, TrustStoreError> {
        Ok(self
            .cache
            .get(serial_number)
            .map(|entry| entry.value().clone()))
    }

    async fn get_cert_by_subject(
        &self,
        subject: &str,
    ) -> Result<Option<CertificateEntry>, TrustStoreError> {
        for entry in self.cache.iter() {
            if entry.value().subject == subject {
                return Ok(Some(entry.value().clone()));
            }
        }
        Ok(None)
    }

    async fn verify<I, D>(&self, der_chain: I) -> Result<bool, TrustStoreError>
    where
        I: IntoIterator<Item = D> + Send,
        D: AsRef<[u8]> + Send,
    {
        let chain_certs = der_chain
            .into_iter()
            .map(|der| CertificateEntry::from_der(der.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        if chain_certs.is_empty() {
            return Ok(false);
        }
        if chain_certs.len() > 10 {
            return Err(TrustStoreError::Custom(eyre!("Certificate chain too long")));
        }

        // Build a chain from end-entity to trusted root
        let trust_chain = match self.build_chain(chain_certs) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::warn!("Unable to build certificate chain: {e}");
                return Ok(false);
            }
        };
        // Verify the certificate path
        self.verify_chain(&trust_chain)
    }

    async fn remove_cert(&self, serial_number: &str) -> Result<bool, TrustStoreError> {
        Ok(self.cache.remove(serial_number).is_some())
    }

    async fn clear(&self) -> Result<(), TrustStoreError> {
        self.cache.clear();
        Ok(())
    }

    async fn iter_all_certificates(&self) -> Result<Vec<CertificateEntry>, TrustStoreError> {
        Ok(self
            .cache
            .iter()
            .map(|entry| entry.value().clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
    use tempfile::TempDir;

    fn gen_ca_cert() -> (Issuer<'static, KeyPair>, CertificateEntry) {
        let mut params = CertificateParams::default();
        let key_pair = KeyPair::generate().unwrap();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA Root");
        dn.push(DnType::OrganizationName, "Test Organization");
        params.distinguished_name = dn;

        params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();
        let entry = CertificateEntry::from_der(der).unwrap();
        let issuer = Issuer::new(params, key_pair);
        (issuer, entry)
    }

    fn gen_leaf_cert(ca: &Issuer<'static, KeyPair>) -> CertificateEntry {
        let mut params = CertificateParams::default();
        let key_pair = KeyPair::generate().unwrap();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test.example.com");
        dn.push(DnType::OrganizationName, "Test Organization");
        params.distinguished_name = dn;

        params.is_ca = rcgen::IsCa::NoCa;
        let cert = params.signed_by(&key_pair, ca).unwrap();
        let der = cert.der();
        CertificateEntry::from_der(der).unwrap()
    }

    #[tokio::test]
    async fn test_add_and_get_cert() {
        let dir = TempDir::new().unwrap();
        let store = MemoryTrustStore::new(dir.path()).await.unwrap();

        let (_, ca_entry) = gen_ca_cert();
        store.add_certs([ca_entry.raw.as_ref()]).await.unwrap();
        assert_eq!(store.len(), 1);

        let by_serial = store
            .get_cert_by_serial(&ca_entry.serial_number)
            .await
            .unwrap();
        assert!(by_serial.is_some());

        let by_subject = store.get_cert_by_subject(&ca_entry.subject).await.unwrap();
        assert!(by_subject.is_some());
        assert_eq!(
            by_serial.unwrap().serial_number,
            by_subject.unwrap().serial_number
        );
    }

    #[tokio::test]
    async fn test_verify_valid_chain() {
        let dir = TempDir::new().unwrap();
        let store = MemoryTrustStore::new(dir.path()).await.unwrap();

        let (ca_issuer, ca_entry) = gen_ca_cert();
        store.add_certs([ca_entry.raw.as_ref()]).await.unwrap();
        assert!(store.len() == 1);

        let leaf_entry = gen_leaf_cert(&ca_issuer);

        let res = store.verify([leaf_entry.raw.as_ref()]).await.unwrap();
        assert!(res);
    }

    #[tokio::test]
    async fn test_verify_empty_chain() {
        let dir = TempDir::new().unwrap();
        let store = MemoryTrustStore::new(dir.path()).await.unwrap();

        let res = store.verify(Vec::<Vec<u8>>::new()).await.unwrap();
        assert!(!res);
    }

    #[tokio::test]
    async fn test_verify_missing_root() {
        let dir = TempDir::new().unwrap();
        let store = MemoryTrustStore::new(dir.path()).await.unwrap();

        let (ca_issuer, _) = gen_ca_cert();
        let leaf_entry = gen_leaf_cert(&ca_issuer);

        // no root ca in store
        let res = store.verify([leaf_entry.raw.as_ref()]).await.unwrap();
        assert!(!res);
    }

    #[tokio::test]
    async fn test_add_corrupted_cert() {
        let dir = TempDir::new().unwrap();
        let store = MemoryTrustStore::new(dir.path()).await.unwrap();

        let good_cert = gen_ca_cert().1;
        let bad_cert = vec![0u8; 10];

        let count = store
            .add_certs([good_cert.raw.as_ref(), &bad_cert])
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.len(), 1);
    }
}
