use std::ffi::CString;
use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use lru::LruCache;
use pcsc::{Context, Protocols, Scope, ShareMode};
use ring::{
    agreement, digest, hkdf,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

use crate::domain::eid::models::{AuthError, ConnectionHandle};

/// Maximum number of trusted root certificates to cache
const MAX_TRUSTED_ROOTS: usize = 100;

/// Maximum size for certificate cache
const MAX_CERTIFICATE_CACHE: usize = 1000;

/// Default challenge size in bytes (256 bits)
const CHALLENGE_SIZE: usize = 32;

/// Default session key size in bytes
const SESSION_KEY_SIZE: usize = 32;


#[derive(Debug, Clone)]
pub struct CertificateStore {
    trusted_roots: Arc<RwLock<Vec<Vec<u8>>>>,
    certificate_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            trusted_roots: Arc::new(RwLock::new(Vec::new())),
            certificate_cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_CERTIFICATE_CACHE).unwrap(),
            ))),
        }
    }

    pub async fn add_trusted_root(&self, certificate_der: Vec<u8>) -> Result<(), AuthError> {
        info!(
            "Adding trusted root certificate ({} bytes)",
            certificate_der.len()
        );

        let (_, parsed_cert) = parse_x509_certificate(&certificate_der).map_err(|e| {
            AuthError::InvalidCertificate {
                details: format!("Failed to parse trusted root certificate: {}", e),
            }
        })?;

        if !self.is_ca_certificate(&parsed_cert) {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate is not a valid CA certificate".to_string(),
            });
        }

        let mut roots = self.trusted_roots.write().await;
        if roots.iter().any(|existing| existing == &certificate_der) {
            warn!("Attempted to add duplicate trusted root certificate");
            return Ok(());
        }

        if roots.len() >= MAX_TRUSTED_ROOTS {
            warn!("Maximum trusted roots limit reached, removing oldest");
            roots.remove(0);
        }

        roots.push(certificate_der);
        info!(
            "Successfully added trusted root certificate. Total roots: {}",
            roots.len()
        );
        Ok(())
    }

    pub async fn validate_certificate_chain(
        &self,
        certificate_der: Vec<u8>,
    ) -> Result<bool, AuthError> {
        debug!(
            "Validating certificate chain ({} bytes)",
            certificate_der.len()
        );

        if certificate_der.is_empty() {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate data is empty".to_string(),
            });
        }

        let cert_hash = self.calculate_certificate_hash(&certificate_der);
        {
            let mut cache = self.certificate_cache.write().await;
            if let Some(cached_der) = cache.get(&cert_hash) {
                debug!("Using cached certificate for validation");
                let (_, cached_cert) = parse_x509_certificate(cached_der).map_err(|e| {
                    AuthError::InvalidCertificate {
                        details: format!("Failed to parse cached certificate: {}", e),
                    }
                })?;
                return self.validate_cached_certificate(&cached_cert).await;
            }
        }

        let (_, cert) = parse_x509_certificate(&certificate_der).map_err(|e| {
            AuthError::InvalidCertificate {
                details: format!("Failed to parse certificate: {}", e),
            }
        })?;

        {
            let mut cache = self.certificate_cache.write().await;
            cache.put(cert_hash, certificate_der.clone());
        }

        self.validate_certificate_properties(&cert)?;
        self.verify_against_trusted_roots(&cert).await
    }

    pub fn verify_certificate_signature(
        &self,
        cert: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
    ) -> Result<bool, AuthError> {
        debug!("Verifying certificate signature");

        let issuer_public_key = issuer.public_key().subject_public_key.data.as_ref();
        let signature = cert.signature_value.data.as_ref();
        let tbs_certificate = cert.tbs_certificate.as_ref();

        let algorithm_result = match cert.signature_algorithm.algorithm.to_string().as_str() {
            "1.2.840.113549.1.1.11" => self.verify_rsa_signature(
                tbs_certificate,
                signature,
                issuer_public_key,
                &signature::RSA_PKCS1_2048_8192_SHA256,
            ),
            "1.2.840.113549.1.1.12" => self.verify_rsa_signature(
                tbs_certificate,
                signature,
                issuer_public_key,
                &signature::RSA_PKCS1_2048_8192_SHA384,
            ),
            "1.2.840.113549.1.1.13" => self.verify_rsa_signature(
                tbs_certificate,
                signature,
                issuer_public_key,
                &signature::RSA_PKCS1_2048_8192_SHA512,
            ),
            "1.2.840.10045.4.3.2" => self.verify_ecdsa_signature(
                tbs_certificate,
                signature,
                issuer_public_key,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            "1.2.840.10045.4.3.3" => self.verify_ecdsa_signature(
                tbs_certificate,
                signature,
                issuer_public_key,
                &signature::ECDSA_P384_SHA384_ASN1,
            ),
            oid => {
                warn!("Unsupported signature algorithm: {}", oid);
                return Err(AuthError::InvalidCertificate {
                    details: format!("Unsupported signature algorithm: {}", oid),
                });
            }
        };

        algorithm_result
    }

    pub async fn get_certificate_permissions(
        &self,
        certificate_der: &[u8],
    ) -> Result<Vec<String>, AuthError> {
        debug!("Extracting certificate permissions");

        let (_, cert) =
            parse_x509_certificate(certificate_der).map_err(|e| AuthError::InvalidCertificate {
                details: format!("Failed to parse certificate: {}", e),
            })?;

        let mut permissions = Vec::new();
        for extension in cert.extensions() {
            match extension.parsed_extension() {
                x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
                    self.process_extended_key_usage(eku, &mut permissions);
                }
                x509_parser::extensions::ParsedExtension::KeyUsage(ku) => {
                    self.process_key_usage(ku, &mut permissions);
                }
                x509_parser::extensions::ParsedExtension::BasicConstraints(bc) => {
                    if bc.ca {
                        permissions.push("certificate_authority".to_string());
                    }
                }
                _ => {}
            }
        }

        if permissions.is_empty() {
            permissions = self.get_default_eid_permissions();
        }

        debug!("Extracted permissions: {:?}", permissions);
        Ok(permissions)
    }

    fn calculate_certificate_hash(&self, certificate_der: &[u8]) -> String {
        let hash = digest::digest(&digest::SHA256, certificate_der);
        hex::encode(hash.as_ref())
    }

    async fn validate_cached_certificate(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<bool, AuthError> {
        self.validate_certificate_properties(cert)?;
        self.verify_against_trusted_roots(cert).await
    }

    fn validate_certificate_properties(&self, cert: &X509Certificate) -> Result<(), AuthError> {
        let now = Utc::now();
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .ok_or_else(|| AuthError::InvalidCertificate {
                details: "Invalid not_before timestamp".to_string(),
            })?;
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .ok_or_else(|| AuthError::InvalidCertificate {
                details: "Invalid not_after timestamp".to_string(),
            })?;

        if now < not_before {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate is not yet valid".to_string(),
            });
        }

        if now > not_after {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate has expired".to_string(),
            });
        }

        Ok(())
    }

    async fn verify_against_trusted_roots(
        &self,
        cert: &X509Certificate<'_>,
    ) -> Result<bool, AuthError> {
        let trusted_roots = self.trusted_roots.read().await;
        if trusted_roots.is_empty() {
            return Err(AuthError::InvalidCertificate {
                details: "No trusted root certificates configured".to_string(),
            });
        }

        for root_der in trusted_roots.iter() {
            let (_, root_cert) =
                parse_x509_certificate(root_der).map_err(|e| AuthError::InvalidCertificate {
                    details: format!("Failed to parse root certificate: {}", e),
                })?;

            if self.verify_certificate_signature(cert, &root_cert)? {
                debug!("Certificate verified against trusted root");
                return Ok(true);
            }
        }

        Err(AuthError::InvalidCertificate {
            details: "Certificate not signed by any trusted root".to_string(),
        })
    }

    fn is_ca_certificate(&self, cert: &X509Certificate) -> bool {
        cert.extensions()
            .iter()
            .find_map(|ext| {
                if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                    ext.parsed_extension()
                {
                    Some(bc.ca)
                } else {
                    None
                }
            })
            .unwrap_or(false)
    }

    // Define verify_rsa_signature
    fn verify_rsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: &'static dyn signature::VerificationAlgorithm,
    ) -> Result<bool, AuthError> {
        let public_key = signature::UnparsedPublicKey::new(algorithm, public_key);
        public_key
            .verify(data, signature)
            .map(|_| true)
            .map_err(|_| AuthError::InvalidCertificate {
                details: "RSA signature verification failed".to_string(),
            })
    }

    // Define verify_ecdsa_signature
    fn verify_ecdsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: &'static dyn signature::VerificationAlgorithm,
    ) -> Result<bool, AuthError> {
        let public_key = signature::UnparsedPublicKey::new(algorithm, public_key);
        public_key
            .verify(data, signature)
            .map(|_| true)
            .map_err(|_| AuthError::InvalidCertificate {
                details: "ECDSA signature verification failed".to_string(),
            })
    }

    fn process_extended_key_usage(
        &self,
        eku: &x509_parser::extensions::ExtendedKeyUsage,
        permissions: &mut Vec<String>,
    ) {
        if eku.server_auth {
            permissions.push("server_authentication".to_string());
        }
        if eku.client_auth {
            permissions.push("client_authentication".to_string());
        }
        if eku.code_signing {
            permissions.push("code_signing".to_string());
        }
        if eku.email_protection {
            permissions.push("email_protection".to_string());
        }
        if eku.time_stamping {
            permissions.push("time_stamping".to_string());
        }
        for oid in &eku.other {
            match oid.to_string().as_str() {
                "1.3.6.1.5.5.7.3.1" => permissions.push("read_identity".to_string()),
                "1.3.6.1.5.5.7.3.2" => permissions.push("write_identity".to_string()),
                _ => {}
            }
        }
    }

    fn process_key_usage(
        &self,
        ku: &x509_parser::extensions::KeyUsage,
        permissions: &mut Vec<String>,
    ) {
        if ku.digital_signature() {
            permissions.push("digital_signature".to_string());
        }
        if ku.key_encipherment() {
            permissions.push("key_encipherment".to_string());
        }
        if ku.data_encipherment() {
            permissions.push("data_encipherment".to_string());
        }
        if ku.key_agreement() {
            permissions.push("key_agreement".to_string());
        }
    }

    fn get_default_eid_permissions(&self) -> Vec<String> {
        vec![
            "read_name".to_string(),
            "read_address".to_string(),
            "age_verification".to_string(),
        ]
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographic provider for eID operations.
///
/// Handles cryptographic operations including key generation, signature verification,
/// key agreement, and secure random number generation.
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// Cryptographically secure random number generator
    rng: Arc<SystemRandom>,
}

impl CryptoProvider {
    /// Creates a new cryptographic provider.
    pub fn new() -> Self {
        Self {
            rng: Arc::new(SystemRandom::new()),
        }
    }

    /// Generates a cryptographic challenge for authentication.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 256-bit random challenge
    /// * `Err(AuthError)` - Random generation error
    pub async fn generate_challenge(&self) -> Result<Vec<u8>, AuthError> {
        debug!("Generating {}-byte cryptographic challenge", CHALLENGE_SIZE);

        let mut challenge = vec![0u8; CHALLENGE_SIZE];
        self.rng.fill(&mut challenge).map_err(|e| {
            error!("Failed to generate challenge: {:?}", e);
            AuthError::CryptoError {
                operation: "Challenge generation".to_string(),
            }
        })?;

        debug!("Successfully generated challenge");
        Ok(challenge)
    }

    /// Verifies a digital signature against provided data.
    ///
    /// Supports multiple signature algorithms and automatically detects
    /// the appropriate verification method.
    ///
    /// # Arguments
    /// * `data` - Original data that was signed
    /// * `signature` - Digital signature to verify
    /// * `public_key_der` - Public key in DER format
    ///
    /// # Returns
    /// * `Ok(true)` - Signature is valid
    /// * `Ok(false)` - Signature is invalid
    /// * `Err(AuthError)` - Verification error
    pub async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key_der: &[u8],
    ) -> Result<bool, AuthError> {
        debug!(
            "Verifying signature: data={} bytes, signature={} bytes, key={} bytes",
            data.len(),
            signature.len(),
            public_key_der.len()
        );

        // Input validation
        if data.is_empty() {
            return Err(AuthError::CryptoError {
                operation: "Signature verification - empty data".to_string(),
            });
        }

        if signature.is_empty() {
            return Err(AuthError::CryptoError {
                operation: "Signature verification - empty signature".to_string(),
            });
        }

        if public_key_der.is_empty() {
            return Err(AuthError::CryptoError {
                operation: "Signature verification - empty public key".to_string(),
            });
        }

        // Try different signature algorithms
        let algorithms = [
            ("RSA-SHA256", &signature::RSA_PKCS1_2048_8192_SHA256),
            ("RSA-SHA384", &signature::RSA_PKCS1_2048_8192_SHA384),
            ("RSA-SHA512", &signature::RSA_PKCS1_2048_8192_SHA512),
        ];

        for (alg_name, algorithm) in &algorithms {
            let public_key = signature::UnparsedPublicKey::new(*algorithm, public_key_der);
            if public_key.verify(data, signature).is_ok() {
                debug!("Signature verified successfully using {}", alg_name);
                return Ok(true);
            }
        }

        debug!("Signature verification failed with all supported algorithms");
        Ok(false)
    }

    /// Performs Elliptic Curve Diffie-Hellman key exchange.
    ///
    /// # Arguments
    /// * `private_key_bytes` - Our private key (currently unused due to ring limitations)
    /// * `peer_public_key` - Peer's public key
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Shared secret
    /// * `Err(AuthError)` - Key exchange error
    ///
    /// # Note
    /// This implementation generates a new ephemeral key due to ring library limitations.
    /// In production, you may want to use a different cryptographic library that allows
    /// key import/export.
    pub async fn perform_ecdh(
        &self,
        _private_key_bytes: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        debug!(
            "Performing ECDH key exchange with peer key ({} bytes)",
            peer_public_key.len()
        );

        if peer_public_key.is_empty() {
            return Err(AuthError::CryptoError {
                operation: "ECDH - empty peer public key".to_string(),
            });
        }

        // Generate ephemeral private key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &*self.rng)
            .map_err(|e| {
                error!("Failed to generate ephemeral private key: {:?}", e);
                AuthError::CryptoError {
                    operation: "ECDH ephemeral key generation".to_string(),
                }
            })?;

        // Create public key from peer's bytes
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);

        // Perform key agreement
        let shared_secret =
            agreement::agree_ephemeral(private_key, &peer_public_key, |shared_secret| {
                Ok(shared_secret.to_vec())
            })
            .map_err(|e| {
                error!("ECDH key agreement failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "ECDH key agreement".to_string(),
                }
            })?;

        debug!("ECDH key exchange completed successfully");
        Ok(shared_secret?)
    }

    /// Derives session keys from a shared secret using HKDF.
    ///
    /// # Arguments
    /// * `shared_secret` - Shared secret from key exchange
    ///
    /// # Returns
    /// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (encryption_key, mac_key)
    /// * `Err(AuthError)` - Key derivation error
    pub async fn derive_session_keys(
        &self,
        shared_secret: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        debug!(
            "Deriving session keys from {}-byte shared secret",
            shared_secret.len()
        );

        if shared_secret.is_empty() {
            return Err(AuthError::CryptoError {
                operation: "Key derivation - empty shared secret".to_string(),
            });
        }

        // HKDF parameters
        let salt = b"eID-Server-v1.0-session-key-derivation-salt";
        let info_enc = b"eID-session-encryption-key";
        let info_mac = b"eID-session-mac-key";

        // Extract phase
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(shared_secret);

        // Expand phase - derive encryption key
        let mut enc_key = vec![0u8; SESSION_KEY_SIZE];
        prk.expand(&[info_enc], hkdf::HKDF_SHA256)
            .map_err(|e| {
                error!("Encryption key derivation failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "Encryption key derivation".to_string(),
                }
            })?
            .fill(&mut enc_key)
            .map_err(|e| {
                error!("Encryption key derivation fill failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "Encryption key derivation fill".to_string(),
                }
            })?;

        // Expand phase - derive MAC key
        let mut mac_key = vec![0u8; SESSION_KEY_SIZE];
        prk.expand(&[info_mac], hkdf::HKDF_SHA256)
            .map_err(|e| {
                error!("MAC key derivation failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "MAC key derivation".to_string(),
                }
            })?
            .fill(&mut mac_key)
            .map_err(|e| {
                error!("MAC key derivation fill failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "MAC key derivation fill".to_string(),
                }
            })?;

        debug!("Successfully derived session keys");
        Ok((enc_key, mac_key))
    }

    /// Generates an ECDH key pair.
    ///
    /// # Returns
    /// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (private_key, public_key)
    /// * `Err(AuthError)` - Key generation error
    ///
    /// # Note
    /// The private key returned is a placeholder due to ring library limitations.
    /// The public key is valid and can be used for key exchange.
    pub async fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        debug!("Generating ECDH keypair");

        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &*self.rng)
            .map_err(|e| {
                error!("Keypair generation failed: {:?}", e);
                AuthError::CryptoError {
                    operation: "ECDH keypair generation".to_string(),
                }
            })?;

        let public_key = private_key.compute_public_key().map_err(|e| {
            error!("Public key computation failed: {:?}", e);
            AuthError::CryptoError {
                operation: "Public key computation".to_string(),
            }
        })?;

        // Note: Ring doesn't expose private key bytes directly
        // In production, consider using a different crypto library
        let private_key_placeholder = vec![0u8; 32]; // Placeholder
        let public_key_bytes = public_key.as_ref().to_vec();

        debug!("Successfully generated keypair");
        Ok((private_key_placeholder, public_key_bytes))
    }

    /// Computes hash of data using specified algorithm.
    ///
    /// # Arguments
    /// * `data` - Data to hash
    /// * `algorithm` - Hash algorithm ("SHA256", "SHA384", "SHA512")
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Hash digest
    /// * `Err(AuthError)` - Unsupported algorithm or hashing error
    pub async fn hash_data(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, AuthError> {
        debug!("Hashing {} bytes with {}", data.len(), algorithm);

        let digest_algorithm = match algorithm.to_uppercase().as_str() {
            "SHA256" => &digest::SHA256,
            "SHA384" => &digest::SHA384,
            "SHA512" => &digest::SHA512,
            _ => {
                return Err(AuthError::CryptoError {
                    operation: format!("Unsupported hash algorithm: {}", algorithm),
                });
            }
        };

        let hash = digest::digest(digest_algorithm, data);
        let result = hash.as_ref().to_vec();

        debug!(
            "Successfully computed {} hash ({} bytes)",
            algorithm,
            result.len()
        );
        Ok(result)
    }
}

impl Default for CryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CardCommunicator {
    timeout: Duration,
}

impl CardCommunicator {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn send_apdu(
        &self,
        connection: &ConnectionHandle,
        apdu: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        println!("Sending APDU to card: {} bytes", apdu.len());

        if !connection.is_valid() {
            return Err(AuthError::InvalidConnection {
                reason: "Invalid connection handle".to_string(),
            });
        }

        // Establish a PC/SC context
        let ctx =
            Context::establish(Scope::User).map_err(|e| AuthError::CardCommunicationError {
                reason: format!("Failed to establish PC/SC context: {}", e),
            })?;

        // Convert ifd_name to CStr
        let reader_name = CString::new(connection.ifd_name.clone()).map_err(|e| {
            AuthError::CardCommunicationError {
                reason: format!("Failed to convert reader name to CStr: {}", e),
            }
        })?;

        // Connect to the card using ifd_name as CStr
        let card = ctx
            .connect(&reader_name, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| AuthError::CardCommunicationError {
                reason: format!("Failed to connect to card: {}", e),
            })?;

        // Allocate response buffer (258 bytes for short APDU + status words)
        let mut response_buf = [0u8; 258];
        let transmit_result = timeout(self.timeout, async {
            card.transmit(apdu, &mut response_buf)
        })
        .await;

        // Handle timeout and transmit result explicitly
        let response: Vec<u8> = match transmit_result {
            Ok(Ok(response_slice)) => {
                // response_slice is &[u8], use it directly
                response_slice.to_vec()
            }
            Ok(Err(e)) => {
                return Err(AuthError::CardCommunicationError {
                    reason: format!("APDU transmission failed: {}", e),
                });
            }
            Err(_) => {
                return Err(AuthError::TimeoutError {
                    operation: "APDU communication".to_string(),
                });
            }
        };

        // Check for success status (0x9000)
        if response.len() >= 2 && response.ends_with(&[0x90, 0x00]) {
            println!(
                "Response length: {}, Response: {:?}",
                response.len(),
                response
            );
            Ok(response)
        } else {
            Err(AuthError::CardCommunicationError {
                reason: format!("APDU command failed with response: {:?}", response),
            })
        }
    }

    pub async fn read_identity_data(
        &self,
        connection: &ConnectionHandle,
        permissions: &[String],
    ) -> Result<String, AuthError> {
        debug!("Reading identity data with permissions: {:?}", permissions);

        if !connection.is_valid() {
            return Err(AuthError::InvalidConnection {
                reason: "Invalid connection handle".to_string(),
            });
        }

        let mut identity_data = serde_json::json!({});
        for permission in permissions {
            match permission.as_str() {
                "read_name" => {
                    let read_name_apdu = vec![0x00, 0xB0, 0x00, 0x01, 0x00];
                    let name_data = self.send_apdu(connection, &read_name_apdu).await?;
                    if name_data.len() < 2 {
                        return Err(AuthError::CardCommunicationError {
                            reason: "APDU response too short".to_string(),
                        });
                    }
                    let name = String::from_utf8(name_data[..name_data.len() - 2].to_vec())
                        .map_err(|e| AuthError::CardCommunicationError {
                            reason: format!("Failed to parse name: {}", e),
                        })?;
                    identity_data["name"] = serde_json::Value::String(name);
                }
                "read_address" => {
                    let read_address_apdu = vec![0x00, 0xB0, 0x00, 0x02, 0x00];
                    let address_data = self.send_apdu(connection, &read_address_apdu).await?;
                    if address_data.len() < 2 {
                        return Err(AuthError::CardCommunicationError {
                            reason: "APDU response too short".to_string(),
                        });
                    }
                    let address =
                        String::from_utf8(address_data[..address_data.len() - 2].to_vec())
                            .map_err(|e| AuthError::CardCommunicationError {
                                reason: format!("Failed to parse address: {}", e),
                            })?;
                    identity_data["address"] = serde_json::Value::String(address);
                }
                _ => continue,
            }
        }

        Ok(identity_data.to_string())
    }
}

impl Default for CardCommunicator {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}
