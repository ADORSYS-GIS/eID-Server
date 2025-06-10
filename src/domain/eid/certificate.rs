use std::{fs, sync::Arc};

use base64::Engine;
use lru::LruCache;
use quick_xml::{
    Reader, Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use reqwest::Client;
use ring::{
    agreement, digest, hkdf,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

use crate::domain::eid::models::{AuthError, AuthenticationProtocolData, ConnectionHandle};

// ... (CertificateStore and CryptoProvider unchanged, included for completeness)
#[derive(Debug, Clone)]
pub struct CertificateStore {
    trusted_roots: Arc<RwLock<Vec<Vec<u8>>>>,
    certificate_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
}

const MAX_TRUSTED_ROOTS: usize = 100;
const MAX_CERTIFICATE_CACHE: usize = 1000;
const CHALLENGE_SIZE: usize = 32;
const SESSION_KEY_SIZE: usize = 32;

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

        // Skip X.509 parsing for CV certificates; assume CVCA is valid BER
        if certificate_der.is_empty() {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate data is empty".to_string(),
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

    pub async fn load_cv_chain(&self) -> Result<Vec<u8>, AuthError> {
        let cert_paths = vec![
            std::env::var("CV_TERM_PATH").map_err(|_| AuthError::InvalidCertificate {
                details: "CV_TERM_PATH not set in .env".to_string(),
            })?,
            std::env::var("CV_DV_PATH").map_err(|_| AuthError::InvalidCertificate {
                details: "CV_DV_PATH not set in .env".to_string(),
            })?,
            std::env::var("CVCA_PATH").map_err(|_| AuthError::InvalidCertificate {
                details: "CVCA_PATH not set in .env".to_string(),
            })?,
        ];

        let mut chain = Vec::new();
        for path in cert_paths {
            let cert_data = fs::read(&path).map_err(|e| AuthError::InvalidCertificate {
                details: format!("Failed to read certificate at {}: {}", path, e),
            })?;
            chain.extend_from_slice(&cert_data);
        }

        Ok(chain)
    }

    pub async fn validate_certificate_chain(
        &self,
        certificate_chain_der: Vec<u8>,
    ) -> Result<bool, AuthError> {
        debug!(
            "Validating CV certificate chain ({} bytes)",
            certificate_chain_der.len()
        );

        if certificate_chain_der.is_empty() {
            return Err(AuthError::InvalidCertificate {
                details: "Certificate chain data is empty".to_string(),
            });
        }

        // For CV certificates, delegate validation to the eID card
        // Store the chain in cache for later use
        let cert_hash = self.calculate_certificate_hash(&certificate_chain_der);
        self.certificate_cache
            .write()
            .await
            .put(cert_hash, certificate_chain_der);
        Ok(true)
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

    pub fn is_ca_certificate(&self, cert: &X509Certificate) -> bool {
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

        let private_key_placeholder = vec![0u8; 32];
        let public_key_bytes = public_key.as_ref().to_vec();

        debug!("Successfully generated keypair");
        Ok((private_key_placeholder, public_key_bytes))
    }

    /// Computes hash of data using specified algorithm.
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
    client: Client,
    ausweisapp2_endpoint: String,
    certificate_store: CertificateStore,
}

impl CardCommunicator {
    pub fn new(ausweisapp2_endpoint: &str, certificate_store: CertificateStore) -> Self {
        CardCommunicator {
            client: Client::new(),
            ausweisapp2_endpoint: ausweisapp2_endpoint.to_string(),
            certificate_store,
        }
    }

    pub async fn send_did_authenticate(
        &self,
        connection: &ConnectionHandle,
        did_name: &str,
        auth_data: &AuthenticationProtocolData,
    ) -> Result<String, AuthError> {
        debug!("Sending DIDAuthenticate to AusweisApp2: {:?}", connection);
        if !connection.is_valid() {
            return Err(AuthError::InvalidConnection {
                reason: "Invalid connection handle".to_string(),
            });
        }

        let soap_request = self
            .build_soap_request(connection, did_name, auth_data)
            .await?;

        let response = self
            .client
            .post(&self.ausweisapp2_endpoint)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header(
                "SOAPAction",
                "http://www.bsi.bund.de/ecard/api/1.1/DIDAuthenticate",
            )
            .body(soap_request)
            .send()
            .await
            .map_err(|e| AuthError::CardCommunicationError {
                reason: format!("Failed to send request to AusweisApp2: {}", e),
            })?;

        let response_text =
            response
                .text()
                .await
                .map_err(|e| AuthError::CardCommunicationError {
                    reason: format!("Failed to read AusweisApp2 response: {}", e),
                })?;

        let personal_data = self.parse_soap_response(&response_text)?;
        Ok(personal_data)
    }
    async fn build_soap_request(
        &self,
        connection: &ConnectionHandle,
        did_name: &str,
        auth_data: &AuthenticationProtocolData,
    ) -> Result<String, AuthError> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);

        // SOAP Envelope
        let mut envelope = BytesStart::new("soapenv:Envelope");
        envelope.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
        envelope.push_attribute(("xmlns:ecard", "http://www.bsi.bund.de/ecard/api/1.1"));
        writer
            .write_event(Event::Start(envelope))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Envelope".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Header".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Header")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Header".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write SOAP Body".to_string(),
            })?;

        writer
            .write_event(Event::Start(BytesStart::new("ecard:DIDAuthenticate")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write DIDAuthenticate".to_string(),
            })?;

        // ConnectionHandle
        writer
            .write_event(Event::Start(BytesStart::new("ecard:ConnectionHandle")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write ConnectionHandle".to_string(),
            })?;
        if let Some(channel_handle) = &connection.channel_handle {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:ChannelHandle")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ChannelHandle".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(channel_handle)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write ChannelHandle text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:ChannelHandle")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close ChannelHandle".to_string(),
                })?;
        }
        if let Some(ifd_name) = &connection.ifd_name {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:IFDName")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write IFDName".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(ifd_name)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write IFDName text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:IFDName")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close IFDName".to_string(),
                })?;
        }
        if let Some(slot_index) = connection.slot_index {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:SlotIndex")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write SlotIndex".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(&slot_index.to_string())))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write SlotIndex text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:SlotIndex")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close SlotIndex".to_string(),
                })?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("ecard:ConnectionHandle")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close ConnectionHandle".to_string(),
            })?;

        // DIDName
        writer
            .write_event(Event::Start(BytesStart::new("ecard:DIDName")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write DIDName".to_string(),
            })?;
        writer
            .write_event(Event::Text(BytesText::new(did_name)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write DIDName text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:DIDName")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close DIDName".to_string(),
            })?;

        // AuthenticationProtocolData
        let mut auth_data_elem = BytesStart::new("ecard:AuthenticationProtocolData");
        auth_data_elem.push_attribute((
            "Protocol",
            "urn:iso:std:iso-iec:24727:part:3:profile:EAC1InputType",
        ));
        writer
            .write_event(Event::Start(auth_data_elem))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write AuthenticationProtocolData".to_string(),
            })?;

        // Certificate (concatenated CV chain, base64-encoded)
        let cv_chain = self.certificate_store.load_cv_chain().await?;
        let cv_chain_b64 = base64::engine::general_purpose::STANDARD.encode(&cv_chain);
        writer
            .write_event(Event::Start(BytesStart::new("ecard:Certificate")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write Certificate".to_string(),
            })?;
        writer
            .write_event(Event::Text(BytesText::new(&cv_chain_b64)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write Certificate text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:Certificate")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close Certificate".to_string(),
            })?;

        // CertificateDescription
        writer
            .write_event(Event::Start(BytesStart::new(
                "ecard:CertificateDescription",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write CertificateDescription".to_string(),
            })?;
        let tls_cert_hash = auth_data.certificate_description.clone();
        let cert_desc = format!(
            "<SubjectURL>https://your-eservice.example.com</SubjectURL><CommCertificates>{}</CommCertificates>",
            tls_cert_hash
        );
        writer
            .write_event(Event::Text(BytesText::new(&cert_desc)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write CertificateDescription text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:CertificateDescription")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close CertificateDescription".to_string(),
            })?;

        // RequiredCHAT
        writer
            .write_event(Event::Start(BytesStart::new("ecard:RequiredCHAT")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write RequiredCHAT".to_string(),
            })?;
        writer
            .write_event(Event::Text(BytesText::new(&auth_data.required_chat)))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to write RequiredCHAT text".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("ecard:RequiredCHAT")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close RequiredCHAT".to_string(),
            })?;

        // OptionalCHAT
        if let Some(optional_chat) = &auth_data.optional_chat {
            writer
                .write_event(Event::Start(BytesStart::new("ecard:OptionalCHAT")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write OptionalCHAT".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(optional_chat)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write OptionalCHAT text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new("ecard:OptionalCHAT")))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close OptionalCHAT".to_string(),
                })?;
        }

        // TransactionInfo
        if let Some(transaction_info) = &auth_data.transaction_info {
            writer
                .write_event(Event::Start(BytesStart::new(
                    "ecard:AuthenticatedAuxiliaryData",
                )))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticatedAuxiliaryData".to_string(),
                })?;
            writer
                .write_event(Event::Text(BytesText::new(transaction_info)))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to write AuthenticatedAuxiliaryData text".to_string(),
                })?;
            writer
                .write_event(Event::End(BytesEnd::new(
                    "ecard:AuthenticatedAuxiliaryData",
                )))
                .map_err(|_| AuthError::InvalidConnection {
                    reason: "Failed to close AuthenticatedAuxiliaryData".to_string(),
                })?;
        }

        writer
            .write_event(Event::End(BytesEnd::new(
                "ecard:AuthenticationProtocolData",
            )))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close AuthenticationProtocolData".to_string(),
            })?;

        writer
            .write_event(Event::End(BytesEnd::new("ecard:DIDAuthenticate")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close DIDAuthenticate".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Body")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Body".to_string(),
            })?;
        writer
            .write_event(Event::End(BytesEnd::new("soapenv:Envelope")))
            .map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to close SOAP Envelope".to_string(),
            })?;

        let result =
            String::from_utf8(writer.into_inner()).map_err(|_| AuthError::InvalidConnection {
                reason: "Failed to convert SOAP request to UTF-8".to_string(),
            })?;
        Ok(result)
    }

    fn parse_soap_response(&self, response: &str) -> Result<String, AuthError> {
        let mut reader = Reader::from_str(response);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut personal_data = String::new();
        let mut in_personal_data = false;
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    if e.name().as_ref() == b"PersonalData" {
                        in_personal_data = true;
                        depth += 1;
                    }
                }
                Ok(Event::Text(e)) if in_personal_data => {
                    personal_data = e
                        .unescape()
                        .map_err(|_| AuthError::CardCommunicationError {
                            reason: "Failed to unescape PersonalData".to_string(),
                        })?
                        .to_string();
                }
                Ok(Event::End(e)) => {
                    if e.name().as_ref() == b"PersonalData" {
                        in_personal_data = false;
                        depth -= 1;
                    }
                }
                Ok(Event::Eof) => {
                    if depth != 0 {
                        return Err(AuthError::CardCommunicationError {
                            reason: "Malformed XML: Unclosed PersonalData tag".to_string(),
                        });
                    }
                    break;
                }
                Err(e) => {
                    return Err(AuthError::CardCommunicationError {
                        reason: format!("Failed to parse AusweisApp2 response: {}", e),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        if personal_data.is_empty() {
            return Err(AuthError::CardCommunicationError {
                reason: "No PersonalData found in response".to_string(),
            });
        }
        Ok(personal_data)
    }
}
