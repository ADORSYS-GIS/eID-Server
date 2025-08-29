
use std::{collections::HashMap, path::PathBuf};
use log::{info};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use rand::{rngs::OsRng, RngCore};
use hex;


use async_trait::async_trait;
use tokio::fs;

use crate::pki::trust_store::{error::TrustStoreError, models::CSCAPublicKeyInfo};

/// A trait defining the interface for persisting and loading the trust store.
#[async_trait]
pub trait TrustStoreRepository {
    /// Loads the certificates from the persistent storage.
    async fn load_certificates(&self) -> Result<HashMap<String, CSCAPublicKeyInfo>, TrustStoreError>;

    /// Saves the given certificates to the persistent storage.
    async fn save_certificates(
        &self,
        certificates: &HashMap<String, CSCAPublicKeyInfo>,
    ) -> Result<(), TrustStoreError>;
}

/// A file-based implementation of the `TrustStoreRepository` trait.
pub struct FileTrustStoreRepository {
    file_path: PathBuf,
    key: [u8; 32],
}

impl FileTrustStoreRepository {
    /// Creates a new `FileTrustStoreRepository` with the specified file path and encryption key.
    pub fn new(file_path: PathBuf, key: [u8; 32]) -> Self {
        Self { file_path, key }
    }
}

#[async_trait]
impl TrustStoreRepository for FileTrustStoreRepository {
    async fn load_certificates(&self) -> Result<HashMap<String, CSCAPublicKeyInfo>, TrustStoreError> {
        info!("Attempting to load certificates from file: {:?}", self.file_path);
        if !self.file_path.exists() {
            info!("No trust store file found at {:?}. Initializing with an empty store.", self.file_path);
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(&self.file_path).await?;
        let combined_data = hex::decode(&content).map_err(|e| TrustStoreError::DecryptionError(format!("Failed to decode hex: {}", e)))?;

        // Ensure combined_data has at least 12 bytes for the nonce
        if combined_data.len() < 12 {
            return Err(TrustStoreError::DecryptionError("Ciphertext too short for nonce".to_string()));
        }

        let (nonce_bytes, ciphertext) = combined_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = ChaCha20Poly1305::new(&self.key.into());

        let plaintext_bytes = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| TrustStoreError::DecryptionError(format!("Failed to decrypt: {}", e)))?;
        
        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|e| TrustStoreError::DecryptionError(format!("Failed to convert to string: {}", e)))?;

        let certificates: HashMap<String, CSCAPublicKeyInfo> =
            serde_json::from_str(&plaintext).map_err(TrustStoreError::SerializationError)?;
        info!("Successfully loaded {} certificates from file: {:?}", certificates.len(), self.file_path);
        Ok(certificates)
    }

    async fn save_certificates(
        &self,
        certificates: &HashMap<String, CSCAPublicKeyInfo>,
    ) -> Result<(), TrustStoreError> {
        info!("Attempting to save {} certificates to file: {:?} (encrypted)", certificates.len(), self.file_path);
        
        let content = serde_json::to_string_pretty(certificates)
            .map_err(TrustStoreError::SerializationError)?;

        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let mut rng = OsRng::default();
        let mut nonce_bytes = [0u8; 12]; // ChaCha20Poly1305 uses a 12-byte nonce
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, content.as_bytes())
            .map_err(|e| TrustStoreError::EncryptionError(format!("Failed to encrypt: {}", e)))?;
        
        let mut combined_data = nonce_bytes.to_vec();
        combined_data.extend_from_slice(&ciphertext);
        let combined_data_hex = hex::encode(combined_data);

        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&self.file_path, combined_data_hex).await?;
        info!("Successfully saved certificates to file: {:?} (encrypted)", self.file_path);
        Ok(())
    }
}
