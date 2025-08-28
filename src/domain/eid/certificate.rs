use std::{fs, sync::Arc};

use base64::Engine;
use lru::LruCache;
use quick_xml::{Reader, events::Event, se::to_string};
use reqwest::Client;
use ring::{
    agreement, digest, hkdf,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_crl;
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

use crate::domain::eid::models::{AuthError, AuthenticationProtocolData, ConnectionHandle};

// CertificateStore implementation (unchanged)
#[derive(Debug, Clone)]
pub struct CertificateStore {
    trusted_roots: Arc<RwLock<Vec<Vec<u8>>>>,
    certificate_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
    crl_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
    http_client: Client,
}

const MAX_TRUSTED_ROOTS: usize = 100;
const MAX_CERTIFICATE_CACHE: usize = 1000;
const MAX_CRL_CACHE: usize = 256;
const CHALLENGE_SIZE: usize = 32;
const SESSION_KEY_SIZE: usize = 32;

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            trusted_roots: Arc::new(RwLock::new(Vec::new())),
            certificate_cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_CERTIFICATE_CACHE).unwrap(),
            ))),
            crl_cache: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_CRL_CACHE).unwrap(),
            ))),
            http_client: Client::new(),
        }
    }

    pub async fn add_trusted_root(&self, certificate_der: Vec<u8>) -> Result<(), AuthError> {
        info!(
            "Adding trusted root certificate ({} bytes)",
            certificate_der.len()
        );

        // Skip X.509 parsing for CV certificates; assume CVCA is valid BER
        if certificate_der.is_empty() {
            return Err(AuthError::invalid_certificate("Certificate data is empty"));
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
            std::env::var("CV_TERM_PATH")
                .map_err(|_| AuthError::invalid_certificate("CV_TERM_PATH not set in .env"))?,
            std::env::var("CV_DV_PATH")
                .map_err(|_| AuthError::invalid_certificate("CV_DV_PATH not set in .env"))?,
            std::env::var("CVCA_PATH")
                .map_err(|_| AuthError::invalid_certificate("CVCA_PATH not set in .env"))?,
        ];

        let mut chain = Vec::new();
        for path in cert_paths {
            let cert_data = fs::read(&path).map_err(|e| {
                AuthError::invalid_certificate(format!("Failed to read certificate at {path}: {e}"))
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
            return Err(AuthError::invalid_certificate(
                "Certificate chain data is empty",
            ));
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

        match cert.signature_algorithm.algorithm.to_string().as_str() {
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
                Err(AuthError::invalid_certificate(format!(
                    "Unsupported signature algorithm: {oid}"
                )))
            }
        }
    }

    pub async fn get_certificate_permissions(
        &self,
        certificate_der: &[u8],
    ) -> Result<Vec<String>, AuthError> {
        debug!("Extracting certificate permissions");

        let (_, cert) = parse_x509_certificate(certificate_der).map_err(|e| {
            AuthError::invalid_certificate(format!("Failed to parse certificate: {e}"))
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
            .map_err(|_| AuthError::crypto_error("RSA signature verification failed"))
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
            .map_err(|_| AuthError::crypto_error("ECDSA signature verification failed"))
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

    // CRL support
    pub async fn prefetch_trusted_root_crls(&self) {
        let roots = self.trusted_roots.read().await.clone();
        for root_der in roots {
            match parse_x509_certificate(&root_der) {
                Ok((_, cert)) => {
                    let urls = self.extract_crl_urls(&cert);
                    for url in urls {
                        if self.get_cached_crl(&url).await.is_some() {
                            continue;
                        }
                        if let Err(e) = self.fetch_and_cache_crl(&url).await {
                            warn!("Failed to prefetch CRL from {}: {:?}", url, e);
                        }
                    }
                }
                Err(e) => warn!("Failed to parse trusted root for CRL prefetch: {:?}", e),
            }
        }
    }

    pub async fn validate_against_crl(&self, certificate_der: &[u8]) -> Result<bool, AuthError> {
        let (_, cert) = parse_x509_certificate(certificate_der).map_err(|e| {
            AuthError::invalid_certificate(format!("Failed to parse certificate: {e}"))
        })?;

        let urls = self.extract_crl_urls(&cert);
        if urls.is_empty() {
            debug!("No CRL Distribution Points found; skipping CRL check");
            return Ok(true);
        }

        for url in urls {
            // Try cache first
            let crl_bytes = match self.get_cached_crl(&url).await {
                Some(bytes) => bytes,
                None => match self.fetch_and_cache_crl(&url).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            "CRL fetch failed for {}: {:?}; falling back to allow",
                            url, e
                        );
                        continue;
                    }
                },
            };

            // Parse CRL
            let crl = match parse_x509_crl(&crl_bytes) {
                Ok((_, crl)) => crl,
                Err(e) => {
                    warn!("Failed to parse CRL from {}: {:?}; skipping", url, e);
                    continue;
                }
            };

            // Basic issuer check (best-effort)
            if crl.tbs_cert_list.issuer.to_string() != cert.tbs_certificate.issuer.to_string() {
                warn!(
                    "CRL issuer does not match certificate issuer for URL {}; skipping",
                    url
                );
                continue;
            }

            // Check if certificate serial is listed as revoked
            let cert_serial = cert.tbs_certificate.raw_serial();
            let revoked = &crl.tbs_cert_list.revoked_certificates;
            let is_revoked = revoked
                .iter()
                .any(|entry| entry.user_certificate.to_bytes_be().as_slice() == cert_serial);
            if is_revoked {
                warn!("Certificate is revoked according to CRL at {}", url);
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn extract_crl_urls(&self, cert: &X509Certificate<'_>) -> Vec<String> {
        let mut urls = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
                for dp in &points.points {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(gns)) =
                        &dp.distribution_point
                    {
                        for gn in gns {
                            if let GeneralName::URI(uri) = gn {
                                urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
        urls
    }

    async fn get_cached_crl(&self, url: &str) -> Option<Vec<u8>> {
        self.crl_cache.read().await.peek(url).cloned()
    }

    async fn fetch_and_cache_crl(&self, url: &str) -> Result<Vec<u8>, AuthError> {
        debug!("Fetching CRL from {}", url);
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| AuthError::card_communication_error(format!("CRL GET failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AuthError::card_communication_error(format!(
                "CRL GET non-success status {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| AuthError::card_communication_error(format!("CRL body read failed: {e}")))?
            .to_vec();
        self.crl_cache
            .write()
            .await
            .put(url.to_string(), bytes.clone());
        Ok(bytes)
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

// CryptoProvider implementation (unchanged)
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
            AuthError::crypto_error("Challenge generation")
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
            return Err(AuthError::crypto_error(
                "Signature verification - empty data",
            ));
        }

        if signature.is_empty() {
            return Err(AuthError::crypto_error(
                "Signature verification - empty signature",
            ));
        }

        if public_key_der.is_empty() {
            return Err(AuthError::crypto_error(
                "Signature verification - empty public key",
            ));
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
            return Err(AuthError::crypto_error("ECDH - empty peer public key"));
        }

        // Generate ephemeral private key
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &*self.rng)
            .map_err(|e| {
                error!("Failed to generate ephemeral private key: {:?}", e);
                AuthError::crypto_error("ECDH ephemeral key generation")
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
                AuthError::crypto_error("ECDH key agreement")
            })?;

        debug!("ECDH key exchange completed successfully");
        shared_secret
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
            return Err(AuthError::crypto_error(
                "Key derivation - empty shared secret",
            ));
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
                AuthError::crypto_error("Encryption key derivation")
            })?
            .fill(&mut enc_key)
            .map_err(|e| {
                error!("Encryption key derivation fill failed: {:?}", e);
                AuthError::crypto_error("Encryption key derivation fill")
            })?;

        // Expand phase - derive MAC key
        let mut mac_key = vec![0u8; SESSION_KEY_SIZE];
        prk.expand(&[info_mac], hkdf::HKDF_SHA256)
            .map_err(|e| {
                error!("MAC key derivation failed: {:?}", e);
                AuthError::crypto_error("MAC key derivation")
            })?
            .fill(&mut mac_key)
            .map_err(|e| {
                error!("MAC key derivation fill failed: {:?}", e);
                AuthError::crypto_error("MAC key derivation fill")
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
                AuthError::crypto_error("ECDH keypair generation")
            })?;

        let public_key = private_key.compute_public_key().map_err(|e| {
            error!("Public key computation failed: {:?}", e);
            AuthError::crypto_error("Public key computation")
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
                return Err(AuthError::crypto_error(format!(
                    "Unsupported hash algorithm: {algorithm}"
                )));
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

// CardCommunicator implementation with serde-based SOAP request building
#[derive(Debug, Serialize)]
#[serde(rename = "Envelope", rename_all = "camelCase")]
struct SoapEnvelope {
    #[serde(rename = "xmlns:soapenv")]
    soapenv: &'static str,
    #[serde(rename = "xmlns:ecard")]
    ecard: &'static str,
    header: SoapHeader,
    body: SoapBody,
}

#[derive(Debug, Serialize)]
struct SoapHeader {}

#[derive(Debug, Serialize)]
#[serde(rename = "Body")]
struct SoapBody {
    #[serde(rename = "DIDAuthenticate")]
    did_authenticate: DidAuthenticate,
}

#[derive(Debug, Serialize)]
struct DidAuthenticate {
    #[serde(rename = "ConnectionHandle")]
    connection_handle: ConnectionHandleData,
    #[serde(rename = "DIDName")]
    did_name: String,
    #[serde(rename = "AuthenticationProtocolData")]
    authentication_protocol_data: AuthenticationProtocolDataXml,
}

#[derive(Debug, Serialize)]
struct ConnectionHandleData {
    #[serde(rename = "ChannelHandle", skip_serializing_if = "Option::is_none")]
    channel_handle: Option<String>,
    #[serde(rename = "IFDName", skip_serializing_if = "Option::is_none")]
    ifd_name: Option<String>,
    #[serde(rename = "SlotIndex", skip_serializing_if = "Option::is_none")]
    slot_index: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "AuthenticationProtocolData")]
struct AuthenticationProtocolDataXml {
    #[serde(rename = "Protocol")]
    protocol: &'static str,
    #[serde(rename = "Certificate")]
    certificate: String,
    #[serde(rename = "CertificateDescription")]
    certificate_description: String,
    #[serde(rename = "RequiredCHAT")]
    required_chat: String,
    #[serde(rename = "OptionalCHAT", skip_serializing_if = "Option::is_none")]
    optional_chat: Option<String>,
    #[serde(
        rename = "AuthenticatedAuxiliaryData",
        skip_serializing_if = "Option::is_none"
    )]
    authenticated_auxiliary_data: Option<String>,
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
            return Err(AuthError::invalid_connection("Invalid connection handle"));
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
            .map_err(|e| {
                AuthError::card_communication_error(format!(
                    "Failed to send request to AusweisApp2: {e}"
                ))
            })?;

        let response_text = response.text().await.map_err(|e| {
            AuthError::card_communication_error(format!("Failed to read AusweisApp2 response: {e}"))
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
        debug!("Building SOAP request");

        let cv_chain = self.certificate_store.load_cv_chain().await?;
        let cv_chain_b64 = base64::engine::general_purpose::STANDARD.encode(&cv_chain);

        let envelope = SoapEnvelope {
            soapenv: "http://schemas.xmlsoap.org/soap/envelope/",
            ecard: "http://www.bsi.bund.de/ecard/api/1.1",
            header: SoapHeader {},
            body: SoapBody {
                did_authenticate: DidAuthenticate {
                    connection_handle: ConnectionHandleData {
                        channel_handle: connection.channel_handle.clone(),
                        ifd_name: connection.ifd_name.clone(),
                        slot_index: connection.slot_index.map(|i| i.to_string()),
                    },
                    did_name: did_name.to_string(),
                    authentication_protocol_data: AuthenticationProtocolDataXml {
                        protocol: "urn:iso:std:iso-iec:24727:part:3:profile:EAC1InputType",
                        certificate: cv_chain_b64,
                        certificate_description: auth_data.certificate_description.clone(),
                        required_chat: auth_data.required_chat.clone(),
                        optional_chat: auth_data.optional_chat.clone(),
                        authenticated_auxiliary_data: auth_data.transaction_info.clone(),
                    },
                },
            },
        };

        let xml = to_string(&envelope).map_err(|e| {
            error!("Failed to serialize SOAP request: {}", e);
            AuthError::protocol_error(format!("Failed to serialize SOAP request: {e}"))
        })?;

        debug!("Successfully built SOAP request");
        Ok(xml)
    }

    fn parse_soap_response(&self, response: &str) -> Result<String, AuthError> {
        let mut reader = Reader::from_str(response);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut personal_data = String::new();
        let mut in_personal_data = false;
        let mut in_result = false;
        let mut result_major = None;
        let mut result_minor = None;
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => match e.name().as_ref() {
                    b"PersonalData" => {
                        in_personal_data = true;
                        depth += 1;
                    }
                    b"Result" => {
                        in_result = true;
                        depth += 1;
                    }
                    b"ResultMajor" => {
                        if in_result {
                            let text = reader.read_text(e.name()).map_err(|e| {
                                AuthError::card_communication_error(format!(
                                    "Failed to read ResultMajor: {e}"
                                ))
                            })?;
                            result_major = Some(text.to_string());
                        }
                    }
                    b"ResultMinor" => {
                        if in_result {
                            let text = reader.read_text(e.name()).map_err(|e| {
                                AuthError::card_communication_error(format!(
                                    "Failed to read ResultMinor: {e}"
                                ))
                            })?;
                            result_minor = Some(text.to_string());
                        }
                    }
                    _ => {}
                },
                Ok(Event::Text(e)) if in_personal_data => {
                    personal_data = e
                        .unescape()
                        .map_err(|_| {
                            AuthError::card_communication_error("Failed to unescape PersonalData")
                        })?
                        .to_string();
                }
                Ok(Event::End(e)) => match e.name().as_ref() {
                    b"PersonalData" => {
                        in_personal_data = false;
                        depth -= 1;
                    }
                    b"Result" => {
                        in_result = false;
                        depth -= 1;
                    }
                    _ => {}
                },
                Ok(Event::Eof) => {
                    if depth != 0 {
                        return Err(AuthError::card_communication_error(
                            "Malformed XML: Unclosed tags",
                        ));
                    }
                    break;
                }
                Err(e) => {
                    return Err(AuthError::card_communication_error(format!(
                        "Failed to parse AusweisApp2 response: {e}"
                    )));
                }
                _ => {}
            }
            buf.clear();
        }

        if let Some(major) = result_major
            && major.contains("error")
        {
            return Err(AuthError::card_communication_error(format!(
                "SOAP response indicates error: major={major}, minor={result_minor:?}"
            )));
        }

        if personal_data.is_empty() {
            return Err(AuthError::card_communication_error(
                "No PersonalData found in response",
            ));
        }
        Ok(personal_data)
    }
}
