use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0} not found")]
    NotFound(String),
    #[error("Key store error: {0}")]
    KeyStore(String),

    #[error("Object store error: {0}")]
    ObjectStore(String),
}

/// Material type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Material {
    /// Terminal CVC key
    CvcKey,
    /// Server key
    X509Key,
    /// Terminal CVC
    TermCvc,
    /// Document Verifier CVC
    DvCvc,
    /// Server X509 certificate
    X509,
    /// Certificate description
    CertDesc,
}

/// Server identity provider
#[derive(Clone)]
pub struct Identity {
    keystore: Arc<dyn Store>,
    object_store: Arc<dyn Store>,
}

impl Identity {
    /// Creates a new identity provider with the specified key and object stores
    pub fn new<K: Store, O: Store>(keystore: K, object_store: O) -> Self {
        Self {
            keystore: Arc::new(keystore),
            object_store: Arc::new(object_store),
        }
    }

    pub async fn upsert(&self, material: Material, blob: impl AsRef<[u8]>) -> Result<(), Error> {
        if matches!(material, Material::CvcKey | Material::X509Key) {
            self.keystore.upsert(material, blob.as_ref()).await
        } else {
            self.object_store.upsert(material, blob.as_ref()).await
        }
    }

    pub async fn get(&self, material: Material) -> Result<Vec<u8>, Error> {
        if matches!(material, Material::CvcKey | Material::X509Key) {
            self.keystore.get(material).await
        } else {
            self.object_store.get(material).await
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Upserts the specified material in the key or object store.
    /// The store is chosen based on the material type.
    async fn upsert(&self, material: Material, blob: &[u8]) -> Result<(), Error>;

    /// Gets the specified material from the key or object store.
    /// The store is chosen based on the material type.
    async fn get(&self, material: Material) -> Result<Vec<u8>, Error>;
}

/// File-based adapter that loads binary files at construction.
/// Intended for development and testing purposes only
#[derive(Debug, Clone)]
pub struct FileIdentity {
    data: Arc<DashMap<Material, Vec<u8>>>,
}

impl FileIdentity {
    /// Creates a new FileIdentity and loads all binary files from the specified directory
    ///
    /// # File naming convention:
    /// - `cvc_key.der` for Material::CvcKey
    /// - `x509_key.der` for Material::X509Key
    /// - `term_cvc.der` for Material::TermCvc
    /// - `dv_cvc.der` for Material::DvCvc
    /// - `x509.der` for Material::X509
    /// - `cert_desc.der` for Material::CertDesc
    pub fn new() -> Self {
        let data = Arc::new(DashMap::new());

        let adapter = Self { data };
        adapter.load_files();
        adapter
    }

    fn load_files(&self) {
        self.data.insert(
            Material::TermCvc,
            include_bytes!("../../test_certs/identity/term_cvc.der").into(),
        );
        self.data.insert(
            Material::DvCvc,
            include_bytes!("../../test_certs/identity/dv_cvc.der").into(),
        );
        self.data.insert(
            Material::X509,
            include_bytes!("../../test_certs/identity/x509.der").into(),
        );
        self.data.insert(
            Material::CertDesc,
            include_bytes!("../../test_certs/identity/cert_desc.der").into(),
        );
        self.data.insert(
            Material::CvcKey,
            include_bytes!("../../test_certs/identity/cvc_key.der").into(),
        );
        self.data.insert(
            Material::X509Key,
            include_bytes!("../../test_certs/identity/x509_key.der").into(),
        );
    }
}

#[async_trait]
impl Store for FileIdentity {
    async fn upsert(&self, _material: Material, _blob: &[u8]) -> Result<(), Error> {
        // We dont need this since we load the files at construction
        Ok(())
    }

    async fn get(&self, material: Material) -> Result<Vec<u8>, Error> {
        self.data
            .get(&material)
            .map(|v| v.clone())
            .ok_or_else(|| Error::NotFound(material_to_string(material).into()))
    }
}

fn material_to_string(material: Material) -> &'static str {
    match material {
        Material::CvcKey => "Terminal CVC Key",
        Material::X509Key => "Server key",
        Material::TermCvc => "Terminal CVC",
        Material::DvCvc => "DV CVC",
        Material::X509 => "Server certificate",
        Material::CertDesc => "Certificate description",
    }
}
