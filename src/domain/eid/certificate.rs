use lru::LruCache;
use quick_xml::{Reader, events::Event, se::to_string};
use reqwest::Client;
use ring::{
    agreement, digest, hkdf,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::Serialize;
use std::{fs, sync::Arc};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use x509_parser::{pem, prelude::X509Certificate};

use crate::domain::eid::models::{
    AuthError, AuthenticationProtocolData, ConnectionHandle, EAC1OutputType, EAC2OutputType,
    EACPhase,
};

// Define ParsedCvc struct at module level
#[derive(Debug)]
pub struct ParsedCvc {
    body: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    tls_cert_hash: Option<Vec<u8>>,
    signature_algorithm: Option<String>,
}

// CertificateStore implementation
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
            "Adding trusted CVCA certificate ({} bytes)",
            certificate_der.len()
        );
        debug!(
            "CVCA certificate (first 20 bytes): {:?}",
            &certificate_der[..certificate_der.len().min(20)]
        );

        if certificate_der.is_empty() {
            return Err(AuthError::invalid_certificate(
                "CVCA certificate data is empty",
            ));
        }

        let mut roots = self.trusted_roots.write().await;
        if roots.iter().any(|existing| existing == &certificate_der) {
            warn!("Attempted to add duplicate CVCA certificate");
            return Ok(());
        }

        if roots.len() >= MAX_TRUSTED_ROOTS {
            warn!("Maximum CVCA certificates limit reached, removing oldest");
            roots.remove(0);
        }

        roots.push(certificate_der);
        info!(
            "Successfully added CVCA certificate. Total roots: {}",
            roots.len()
        );
        Ok(())
    }

    fn pem_parse(data: Vec<u8>) -> Result<pem::Pem, String> {
        let (remaining, pem) = pem::parse_x509_pem(&data)
            .map_err(|e| format!("Failed to parse PEM certificate: {}", e))?;

        if !remaining.is_empty() {
            return Err("Extra data after PEM certificate".to_string());
        }

        Ok(pem)
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
        for (i, path) in cert_paths.iter().enumerate() {
            let cert_data = fs::read(&path).map_err(|e| {
                AuthError::invalid_certificate(format!("Failed to read certificate at {path}: {e}"))
            })?;

            if cert_data.is_empty() {
                return Err(AuthError::invalid_certificate(format!(
                    "Empty certificate file at {path}"
                )));
            }

            // Validate CV certificate structure
            if cert_data.len() < 2 || cert_data[0] != 0x7F || cert_data[1] != 0x21 {
                return Err(AuthError::invalid_certificate(format!(
                    "Certificate at {path} is not a CV certificate (expected 0x7F21, got {:02x}{:02x})",
                    cert_data[0],
                    cert_data.get(1).unwrap_or(&0)
                )));
            }

            // Parse to extract CertificateHolderReference (for debugging)
            let parsed_cvc = Self::parse_cvc(&cert_data).map_err(|e| {
                AuthError::invalid_certificate(format!(
                    "Failed to parse certificate at {path}: {e}"
                ))
            })?;
            let holder_ref = Self::extract_holder_reference(&cert_data).unwrap_or_default();
            debug!(
                "Loaded certificate from {} ({} bytes, holder_ref: {}, first 20 bytes: {:02x?})",
                path,
                cert_data.len(),
                holder_ref,
                &cert_data[..cert_data.len().min(20)]
            );

            chain.extend_from_slice(&cert_data);
        }

        if chain.is_empty() {
            return Err(AuthError::invalid_certificate(
                "No valid certificates found in chain",
            ));
        }

        debug!("Loaded certificate chain ({} bytes)", chain.len());
        Ok(chain)
    }

    // Add helper method to extract CertificateHolderReference
    fn extract_holder_reference(data: &[u8]) -> Option<String> {
        let mut pos = 0;
        while pos + 2 < data.len() {
            if data[pos] == 0x5F && data[pos + 1] == 0x20 {
                // appl [ 32 ]
                let (len, len_bytes) = Self::parse_der_length(&data[pos + 2..]).ok()?;
                if pos + 2 + len_bytes + len <= data.len() {
                    let holder_ref = &data[pos + 2 + len_bytes..pos + 2 + len_bytes + len];
                    return Some(String::from_utf8_lossy(holder_ref).to_string());
                }
                break;
            }
            pos += 1;
        }
        None
    }

    pub async fn validate_certificate_chain(
        &self,
        certificate_chain_der: Vec<u8>,
    ) -> Result<bool, AuthError> {
        // 1. Split and parse the certificate chain (eService CV -> DV -> CVCA)
        let certs = self.split_concatenated_der(&certificate_chain_der)?;
        if certs.len() < 3 {
            return Err(AuthError::invalid_certificate(
                "Certificate chain must contain eService CV, DV, and CVCA certificates",
            ));
        }

        // 2. Parse all certificates
        let mut parsed_certs = Vec::new();
        for (i, cert) in certs.iter().enumerate() {
            let cert_type = match i {
                0 => "eService CV",
                1 => "DV",
                2 => "CVCA",
                _ => "Unknown",
            };
            parsed_certs.push(Self::parse_cvc(cert).map_err(|e| {
                AuthError::invalid_certificate(format!(
                    "Failed to parse {} certificate: {}",
                    cert_type, e
                ))
            })?);
        }

        // 4. Verify CVCA certificate is trusted
        if !self.is_trusted_root(certs.last().unwrap()).await? {
            return Err(AuthError::invalid_certificate(
                "CVCA certificate is not in trusted store",
            ));
        }

        Ok(true)
    }

    fn parse_cvc(data: &[u8]) -> Result<ParsedCvc, String> {
        debug!("Parsing CVC certificate (len: {} bytes)", data.len());
        debug!("First 20 bytes: {:?}", &data[..data.len().min(20)]);
        debug!("Full certificate data (hex): {}", hex::encode(data));
        let mut pos = 0;

        // 1. Check outer tag (0x7F21 - CardVerifiableCertificate)
        if pos + 2 > data.len() || data[pos] != 0x7F || data[pos + 1] != 0x21 {
            return Err("Invalid CVC outer tag (expected 0x7F21)".to_string());
        }
        pos += 2;

        // 2. Parse outer length
        let (outer_len, len_bytes) = Self::parse_der_length(&data[pos..])?;
        debug!("Outer length: {}, length bytes: {}", outer_len, len_bytes);
        pos += len_bytes;

        if pos + outer_len > data.len() {
            return Err(format!(
                "Outer structure truncated: expected {} bytes, got {}",
                outer_len,
                data.len() - pos
            ));
        }

        // 3. Parse CertificateBody (tag 0x7F4E)
        if pos + 2 > data.len() || data[pos] != 0x7F || data[pos + 1] != 0x4E {
            return Err("Invalid CVC body tag (expected 0x7F4E)".to_string());
        }
        pos += 2;

        let (body_len, len_bytes) = Self::parse_der_length(&data[pos..])?;
        debug!("Body length: {}, length bytes: {}", body_len, len_bytes);
        pos += len_bytes;

        let body_end = pos + body_len;
        if body_end > data.len() {
            return Err("CVC body extends beyond input data".to_string());
        }

        // Extract the full CertificateBody including tag and length for signing
        let body = data[pos - 4 - len_bytes..body_end].to_vec(); // Include 0x7F4E and length bytes
        debug!(
            "Extracted body (len: {} bytes, hex): {}",
            body.len(),
            hex::encode(&body)
        );
        pos = body_end;

        // 4. Parse signature (tag 0x5F37)
        if pos + 2 > data.len() || data[pos] != 0x5F || data[pos + 1] != 0x37 {
            return Err("Invalid CVC signature tag (expected 0x5F37)".to_string());
        }
        pos += 2;

        let (sig_len, len_bytes) = Self::parse_der_length(&data[pos..])?;
        debug!("Signature length: {}, length bytes: {}", sig_len, len_bytes);
        pos += len_bytes;

        if pos + sig_len > data.len() {
            return Err("CVC signature extends beyond input data".to_string());
        }

        let signature = data[pos..pos + sig_len].to_vec();
        debug!("Extracted signature (hex): {}", hex::encode(&signature));

        // 5. Extract public key from body
        let public_key = Self::extract_public_key_from_body(&body)?;
        debug!("Extracted public key (hex): {}", hex::encode(&public_key));

        // 6. Extract TLS certificate hash
        let tls_cert_hash = Self::extract_tls_cert_hash(&body)?;
        debug!(
            "TLS certificate hash: {:?}",
            tls_cert_hash.as_ref().map(hex::encode)
        );

        // 7. Extract signature algorithm OID from body
        let signature_algorithm = Self::extract_signature_algorithm(&body)?;
        debug!(
            "Assigned signature algorithm to ParsedCvc: {:?}",
            signature_algorithm
        );

        Ok(ParsedCvc {
            body,
            signature,
            public_key,
            tls_cert_hash,
            signature_algorithm,
        })
    }

    fn extract_signature_algorithm(body: &[u8]) -> Result<Option<String>, String> {
        let mut pos = 0;
        while pos + 2 < body.len() {
            if body[pos] == 0x06 {
                // OID tag
                let oid_len = body[pos + 1] as usize;
                if pos + 2 + oid_len > body.len() {
                    return Err("OID extends beyond body".to_string());
                }

                // Check for known German eID signature algorithm OIDs
                let oid_bytes = &body[pos + 2..pos + 2 + oid_len];

                // German eID OIDs for ECDSA with SHA256
                if oid_bytes == [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x02]
                    || oid_bytes == [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03]
                {
                    debug!("Detected German eID ECDSA-SHA256 signature algorithm");
                    return Ok(Some("1.2.840.10045.4.3.2".to_string()));
                }

                // German eID OID for ECDSA with SHA384
                if oid_bytes == [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x04] {
                    debug!("Detected German eID ECDSA-SHA384 signature algorithm");
                    return Ok(Some("1.2.840.10045.4.3.3".to_string()));
                }

                // Standard OIDs
                if oid_bytes == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] {
                    // ECDSA-SHA256
                    debug!("Detected standard ECDSA-SHA256 signature algorithm");
                    return Ok(Some("1.2.840.10045.4.3.2".to_string()));
                }

                if oid_bytes == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] {
                    // ECDSA-SHA384
                    debug!("Detected standard ECDSA-SHA384 signature algorithm");
                    return Ok(Some("1.2.840.10045.4.3.3".to_string()));
                }

                pos += 2 + oid_len;
            } else {
                pos += 1;
            }
        }

        debug!("No recognized signature algorithm OID found");
        Ok(None)
    }

    fn extract_tls_cert_hash(body: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut pos = 0;
        while pos + 2 < body.len() {
            // Look for the CertificateDescription extension (OID 0.4.0.127.0.7.3.1.3.1)
            if body[pos] == 0x06
                && body[pos + 1] == 0x09
                && pos + 11 <= body.len()
                && &body[pos + 2..pos + 11]
                    == [0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x03, 0x01]
            {
                pos += 11;
                if pos + 1 >= body.len() {
                    return Err("TLS certificate hash extends beyond body".to_string());
                }
                let hash_len = body[pos + 1] as usize;
                if pos + 2 + hash_len > body.len() {
                    return Err("TLS certificate hash extends beyond body".to_string());
                }
                return Ok(Some(body[pos + 2..pos + 2 + hash_len].to_vec()));
            }
            pos += 1;
        }
        Ok(None)
    }

    fn extract_public_key_from_body(body: &[u8]) -> Result<Vec<u8>, String> {
        let mut pos = 0;
        while pos + 2 < body.len() {
            if body[pos] == 0x86 {
                let key_len = body[pos + 1] as usize;
                if pos + 2 + key_len > body.len() {
                    return Err("Public key extends beyond body".to_string());
                }
                let key_data = &body[pos + 2..pos + 2 + key_len];

                // Check for EC public key format (uncompressed)
                if key_data.len() >= 2 && key_data[0] == 0x03 {
                    let bit_string_len = key_data[1] as usize;
                    if key_data.len() >= 2 + bit_string_len && key_data[2] == 0x00 {
                        let pub_key = key_data[3..2 + bit_string_len].to_vec();
                        if (pub_key.len() == 65 || pub_key.len() == 97) && pub_key[0] == 0x04 {
                            debug!(
                                "Extracted valid uncompressed EC public key (length: {} bytes)",
                                pub_key.len()
                            );
                            return Ok(pub_key);
                        } else {
                            return Err(format!(
                                "Invalid EC public key format: length={}, first_byte={:02x}",
                                pub_key.len(),
                                pub_key.get(0).map_or(0, |b| *b)
                            ));
                        }
                    }
                }

                // Handle raw public key data (common in German eID certificates)
                if key_data.len() == 65 && key_data[0] == 0x04 {
                    debug!(
                        "Extracted valid uncompressed EC P-256 public key (raw, length: {} bytes)",
                        key_data.len()
                    );
                    return Ok(key_data.to_vec());
                } else {
                    return Err(format!(
                        "Invalid raw public key format: length={}, first_byte={:02x}",
                        key_data.len(),
                        key_data.get(0).map_or(0, |b| *b)
                    ));
                }
            }
            pos += 1;
        }
        Err("Public key (0x86 tag) not found in body".to_string())
    }

    fn parse_der_length(data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty length field".to_string());
        }

        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            // Short form - single byte length
            Ok((first_byte as usize, 1))
        } else {
            // Long form - multiple byte length
            let len_bytes = (first_byte & 0x7F) as usize;
            if len_bytes == 0 {
                return Err("Indefinite length not supported".to_string());
            }
            if len_bytes > 4 {
                return Err(format!(
                    "Length too large ({} bytes, max 4 supported)",
                    len_bytes
                ));
            }
            if data.len() < 1 + len_bytes {
                return Err(format!(
                    "Insufficient data for length (need {} bytes, got {})",
                    1 + len_bytes,
                    data.len()
                ));
            }

            let mut length = 0usize;
            for i in 0..len_bytes {
                length = (length << 8) | data[1 + i] as usize;
            }

            // Basic sanity check
            if length > 10 * 1024 * 1024 {
                return Err(format!("Implausible large length: {} bytes", length));
            }

            Ok((length, 1 + len_bytes))
        }
    }

    pub fn split_concatenated_der(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, AuthError> {
        let mut certs = Vec::new();
        let mut pos = 0;

        debug!("Input certificate chain length: {} bytes", data.len());
        debug!(
            "First 20 bytes of input: {:02x?}",
            &data[..data.len().min(20)]
        );

        while pos < data.len() {
            if data.len() > pos + 1 && data[pos] == 0x7F && data[pos + 1] == 0x21 {
                let parse_result = Self::parse_der_length(&data[pos + 2..]).map_err(|e| {
                    AuthError::invalid_certificate(format!(
                        "Failed to parse DER length at position {}: {}",
                        pos, e
                    ))
                })?;
                let (body_len, header_len) = parse_result;
                let total_len = 2 + header_len + body_len;

                if data.len() < pos + total_len {
                    return Err(AuthError::invalid_certificate(format!(
                        "CV certificate truncated at position {}: expected {} bytes, got {}",
                        pos,
                        total_len,
                        data.len() - pos
                    )));
                }

                let cert = &data[pos..pos + total_len];
                let holder_ref = Self::extract_holder_reference(cert).unwrap_or_default();
                debug!(
                    "Found certificate at position {}, length: {} bytes, holder_ref: {}",
                    pos, total_len, holder_ref
                );
                certs.push(cert.to_vec());
                pos += total_len;
            } else {
                return Err(AuthError::invalid_certificate(format!(
                    "Unknown certificate format at position {}. First bytes: {:02X} {:02X}",
                    pos,
                    data[pos],
                    data.get(pos + 1).unwrap_or(&0)
                )));
            }
        }

        if certs.is_empty() {
            return Err(AuthError::invalid_certificate(
                "No valid CV certificates found in chain",
            ));
        }

        debug!("Extracted {} certificates from chain", certs.len());
        Ok(certs)
    }
    async fn is_trusted_root(&self, cert: &[u8]) -> Result<bool, AuthError> {
        let roots = self.trusted_roots.read().await;
        Ok(roots.iter().any(|root| root == cert))
    }

    // Rest of the methods remain unchanged
    pub fn verify_certificate_signature(
        &self,
        cert: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
    ) -> Result<bool, AuthError> {
        debug!("Verifying certificate signature");

        let issuer_public_key = issuer.public_key().subject_public_key.data.as_ref();
        let signature = cert.signature_value.data.as_ref();
        let tbs_certificate = cert.tbs_certificate.as_ref();

        // Handle German eID special case
        let signature = if signature.len() == 64 {
            // Convert raw signature to ASN.1 format
            let r = &signature[..32];
            let s = &signature[32..];

            let mut asn1_sig = Vec::with_capacity(72);
            asn1_sig.push(0x30); // SEQUENCE
            asn1_sig.push(0x44); // Length
            asn1_sig.push(0x02); // INTEGER
            asn1_sig.push(0x20); // Length
            asn1_sig.extend_from_slice(r);
            asn1_sig.push(0x02); // INTEGER
            asn1_sig.push(0x20); // Length
            asn1_sig.extend_from_slice(s);

            asn1_sig
        } else {
            signature.to_vec()
        };

        match cert.signature_algorithm.algorithm.to_string().as_str() {
            "1.2.840.10045.4.3.2" => self.verify_ecdsa_signature(
                tbs_certificate,
                &signature,
                issuer_public_key,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            // ... other cases remain the same
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
        debug!("Extracting certificate permissions from CV certificate");

        let parsed_cvc = Self::parse_cvc(certificate_der).map_err(|e| {
            AuthError::invalid_certificate(format!("Failed to parse CV certificate: {e}"))
        })?;

        // Extract permissions from CertificateHolderAuthorizationTemplate
        let mut permissions = Self::extract_chat_permissions(&parsed_cvc.body)?;
        if permissions.is_empty() {
            permissions = self.get_default_eid_permissions();
        }

        debug!("Extracted permissions: {:?}", permissions);
        Ok(permissions)
    }

    fn extract_chat_permissions(body: &[u8]) -> Result<Vec<String>, AuthError> {
        let mut permissions = Vec::new();
        // Placeholder: Parse CertificateHolderAuthorizationTemplate (CHAT)
        // Assuming CHAT is encoded in a specific tag, e.g., 0x7F4C
        let mut pos = 0;
        while pos + 2 < body.len() {
            if body[pos] == 0x7F && body[pos + 1] == 0x4C {
                // Simplified CHAT parsing
                let chat_data = &body[pos + 2..];
                if chat_data.contains(&0x01) {
                    permissions.push("read_identity".to_string());
                }
                if chat_data.contains(&0x02) {
                    permissions.push("write_identity".to_string());
                }
                // Add more attribute-specific permissions as needed
                break;
            }
            pos += 1;
        }
        Ok(permissions)
    }

    // fn verify_rsa_signature(
    //     &self,
    //     data: &[u8],
    //     signature: &[u8],
    //     public_key: &[u8],
    //     algorithm: &'static signature::RsaParameters,
    // ) -> Result<bool, AuthError> {
    //     let public_key = signature::UnparsedPublicKey::new(algorithm, public_key);
    //     public_key
    //         .verify(data, signature)
    //         .map(|_| true)
    //         .map_err(|_| AuthError::crypto_error("RSA signature verification failed"))
    // }

    // Define verify_ecdsa_signature
    fn verify_ecdsa_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: &'static signature::EcdsaVerificationAlgorithm,
    ) -> Result<bool, AuthError> {
        let public_key = signature::UnparsedPublicKey::new(algorithm, public_key);
        public_key
            .verify(data, signature)
            .map(|_| true)
            .map_err(|_| AuthError::crypto_error("ECDSA signature verification failed"))
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

// CryptoProvider implementation
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

        // Try RSA algorithms first
        let rsa_algorithms = [
            ("RSA-SHA256", &signature::RSA_PKCS1_2048_8192_SHA256),
            ("RSA-SHA384", &signature::RSA_PKCS1_2048_8192_SHA384),
            ("RSA-SHA512", &signature::RSA_PKCS1_2048_8192_SHA512),
        ];

        for (alg_name, algorithm) in &rsa_algorithms {
            let public_key = signature::UnparsedPublicKey::new(*algorithm, public_key_der);
            if public_key.verify(data, signature).is_ok() {
                debug!("Signature verified successfully using {}", alg_name);
                return Ok(true);
            }
        }

        // Then try ECDSA algorithms
        let ecdsa_algorithms = [
            ("ECDSA P256", &signature::ECDSA_P256_SHA256_ASN1),
            ("ECDSA P384", &signature::ECDSA_P384_SHA384_ASN1),
            ("ECDSA P256 (Raw)", &signature::ECDSA_P256_SHA256_FIXED),
            ("ECDSA P384 (Raw)", &signature::ECDSA_P384_SHA384_FIXED),
        ];

        for (alg_name, algorithm) in &ecdsa_algorithms {
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

        let salt = b"eID-Server-v1.0-session-key-derivation-salt";
        let info_enc = b"eID-session-encryption-key";
        let info_mac = b"eID-session-mac-key";

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(shared_secret);

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

    pub async fn hash_data(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, AuthError> {
        debug!("Hashing {} bytes with {}", data.len(), algorithm);

        // In the hash_data function, remove SHA1 from the match:
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

// Define structs for XML serialization
#[derive(Debug, Serialize)]
#[serde(rename = "ecard:DIDAuthenticate")]
#[serde(rename_all = "PascalCase")]
pub struct DidAuthenticate {
    #[serde(rename = "xmlns:ecard")]
    xmlns_ecard: &'static str,
    #[serde(rename = "xmlns:iso")]
    xmlns_iso: &'static str,
    connection_handle: ConnectionHandleXml,
    did_name: String,
    authentication_protocol_data: AuthenticationProtocolDataXml,
}

#[derive(Debug, Serialize)]
#[serde(rename = "iso:ConnectionHandle")]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionHandleXml {
    channel_handle: Option<String>,
    ifd_name: Option<String>,
    slot_index: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "iso:AuthenticationProtocolData")]
#[serde(rename_all = "PascalCase")]
pub enum AuthenticationProtocolDataXml {
    EAC1(EAC1InputXml),
    EAC2(EAC2InputXml),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EAC1InputXml {
    protocol: &'static str,
    certificate: String,
    certificate_description: String,
    required_chat: String,
    optional_chat: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EAC2InputXml {
    protocol: &'static str,
    ephemeral_public_key: String,
    signature: String,
}

#[derive(Debug, Clone)]
pub struct CardCommunicator {
    client: Client,
    ausweisapp2_endpoint: String,
    certificate_store: CertificateStore,
}

impl CardCommunicator {
    pub fn new(ausweisapp2_endpoint: &str, certificate_store: CertificateStore) -> Self {
        Self {
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
        send_request: bool,
    ) -> Result<String, AuthError> {
        debug!(
            "Preparing DIDAuthenticate for AusweisApp2 at {} with phase: {:?}, send_request: {}",
            self.ausweisapp2_endpoint, auth_data.phase, send_request
        );
        if !connection.is_valid() {
            return Err(AuthError::invalid_connection("Invalid connection handle"));
        }

        let soap_request = self
            .build_soap_request(connection, did_name, auth_data)
            .await?;

        debug!("SOAP request: {}", soap_request);

        if !send_request {
            // Return the SOAP request for PAOS channel
            return Ok(soap_request);
        }

        // Send HTTP POST (for non-PAOS or testing scenarios)
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

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            AuthError::card_communication_error(format!("Failed to read AusweisApp2 response: {e}"))
        })?;

        // Log the full response for debugging
        debug!(
            "AusweisApp2 response (status: {}): {}",
            status, response_text
        );

        if !status.is_success() {
            return Err(AuthError::card_communication_error(format!(
                "AusweisApp2 returned non-success status: {}. Response: {}",
                status, response_text
            )));
        }

        // Check if response contains HTML
        if response_text.contains("<html") || response_text.contains("</head>") {
            return Err(AuthError::card_communication_error(format!(
                "Received unexpected HTML response from AusweisApp2: {}",
                response_text
            )));
        }

        match auth_data.phase {
            EACPhase::EAC1 => self.parse_eac1_response(&response_text),
            EACPhase::EAC2 => self.parse_eac2_response(&response_text),
        }
    }

    pub async fn build_soap_request(
        &self,
        connection: &ConnectionHandle,
        did_name: &str,
        auth_data: &AuthenticationProtocolData,
    ) -> Result<String, AuthError> {
        let protocol = match auth_data.phase {
            EACPhase::EAC1 => "urn:iso:std:iso-iec:24727:tech:schema:EAC1InputType",
            EACPhase::EAC2 => "urn:iso:std:iso-iec:24727:tech:schema:EAC2InputType",
        };

        let auth_protocol_data = match auth_data.phase {
            EACPhase::EAC1 => {
                let eac1_input = auth_data
                    .eac1_input
                    .as_ref()
                    .ok_or_else(|| AuthError::protocol_error("Missing EAC1 input data"))?;
                format!(
                    r#"<iso:AuthenticationProtocolData>
                        <iso:Protocol>{}</iso:Protocol>
                        <iso:Certificate>{}</iso:Certificate>
                        <iso:CertificateDescription>{}</iso:CertificateDescription>
                        <iso:RequiredCHAT>{}</iso:RequiredCHAT>
                        <iso:OptionalCHAT>{}</iso:OptionalCHAT>
                    </iso:AuthenticationProtocolData>"#,
                    protocol,
                    eac1_input.certificate,
                    eac1_input.certificate_description,
                    eac1_input.required_chat,
                    eac1_input.optional_chat.as_deref().unwrap_or("")
                )
            }
            EACPhase::EAC2 => {
                let eac2_input = auth_data
                    .eac2_input
                    .as_ref()
                    .ok_or_else(|| AuthError::protocol_error("Missing EAC2 input data"))?;
                format!(
                    r#"<iso:AuthenticationProtocolData>
                        <iso:Protocol>{}</iso:Protocol>
                        <iso:EphemeralPublicKey>{}</iso:EphemeralPublicKey>
                        <iso:Signature>{}</iso:Signature>
                    </iso:AuthenticationProtocolData>"#,
                    protocol, eac2_input.ephemeral_public_key, eac2_input.signature
                )
            }
        };

        let soap = format!(
            r#"<ecard:DIDAuthenticate xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
                <iso:ConnectionHandle>
                    <iso:ChannelHandle>{}</iso:ChannelHandle>
                    <iso:IFDName>{}</iso:IFDName>
                    <iso:SlotIndex>{}</iso:SlotIndex>
                </iso:ConnectionHandle>
                <iso:DIDName>{}</iso:DIDName>
                {}
            </ecard:DIDAuthenticate>"#,
            connection.channel_handle.as_deref().unwrap_or(""),
            connection.ifd_name.as_deref().unwrap_or(""),
            connection.slot_index.unwrap_or(0),
            did_name,
            auth_protocol_data
        );

        Ok(soap)
    }

    fn parse_eac1_response(&self, response: &str) -> Result<String, AuthError> {
        let mut reader = Reader::from_str(response);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut in_result = false;
        let mut result_major = None;
        let mut result_minor = None;
        let mut chat = String::new();
        let mut car = String::new();
        let mut ef_card_access = String::new();
        let mut id_picc = String::new();
        let mut challenge = String::new();
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    match e.name().as_ref() {
                        b"Result" => in_result = true,
                        b"CertificateHolderAuthorizationTemplate" => {
                            chat = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read CertificateHolderAuthorizationTemplate: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"CertificationAuthorityReference" => {
                            car = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read CertificationAuthorityReference: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"EFCardAccess" => {
                            ef_card_access = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read EFCardAccess: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"IDPICC" => {
                            id_picc = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read IDPICC: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"Challenge" => {
                            challenge = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read Challenge: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"ResultMajor" => {
                            if in_result {
                                result_major = Some(
                                    reader
                                        .read_text(e.name())
                                        .map_err(|e| {
                                            AuthError::card_communication_error(format!(
                                                "Failed to read ResultMajor: {e}"
                                            ))
                                        })?
                                        .to_string(),
                                );
                            }
                        }
                        b"ResultMinor" => {
                            if in_result {
                                result_minor = Some(
                                    reader
                                        .read_text(e.name())
                                        .map_err(|e| {
                                            AuthError::card_communication_error(format!(
                                                "Failed to read ResultMinor: {e}"
                                            ))
                                        })?
                                        .to_string(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    depth -= 1;
                    if e.name().as_ref() == b"Result" {
                        in_result = false;
                    }
                }
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

        if let Some(major) = result_major {
            if major.contains("error") {
                return Err(AuthError::card_communication_error(format!(
                    "SOAP response indicates error: major={major}, minor={result_minor:?}"
                )));
            }
        }

        if chat.is_empty()
            || car.is_empty()
            || ef_card_access.is_empty()
            || id_picc.is_empty()
            || challenge.is_empty()
        {
            return Err(AuthError::card_communication_error(
                "Missing required EAC1 output fields in response",
            ));
        }

        // Return serialized EAC1OutputType as a string (or adjust as needed)
        let output = EAC1OutputType {
            certificate_holder_authorization_template: chat,
            certification_authority_reference: car,
            ef_card_access,
            id_picc,
            challenge,
        };
        serde_json::to_string(&output).map_err(|e| {
            AuthError::card_communication_error(format!("Failed to serialize EAC1 output: {e}"))
        })
    }

    fn parse_eac2_response(&self, response: &str) -> Result<String, AuthError> {
        let mut reader = Reader::from_str(response);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut in_result = false;
        let mut result_major = None;
        let mut result_minor = None;
        let mut ef_card_security = String::new();
        let mut authentication_token = String::new();
        let mut nonce = String::new();
        let mut challenge = String::new();
        let mut is_type_a = false;
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    match e.name().as_ref() {
                        b"Result" => in_result = true,
                        b"EFCardSecurity" => {
                            ef_card_security = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read EFCardSecurity: {e}"
                                    ))
                                })?
                                .to_string();
                            is_type_a = true;
                        }
                        b"AuthenticationToken" => {
                            authentication_token = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read AuthenticationToken: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"Nonce" => {
                            nonce = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read Nonce: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"Challenge" => {
                            challenge = reader
                                .read_text(e.name())
                                .map_err(|e| {
                                    AuthError::card_communication_error(format!(
                                        "Failed to read Challenge: {e}"
                                    ))
                                })?
                                .to_string();
                        }
                        b"ResultMajor" => {
                            if in_result {
                                result_major = Some(
                                    reader
                                        .read_text(e.name())
                                        .map_err(|e| {
                                            AuthError::card_communication_error(format!(
                                                "Failed to read ResultMajor: {e}"
                                            ))
                                        })?
                                        .to_string(),
                                );
                            }
                        }
                        b"ResultMinor" => {
                            if in_result {
                                result_minor = Some(
                                    reader
                                        .read_text(e.name())
                                        .map_err(|e| {
                                            AuthError::card_communication_error(format!(
                                                "Failed to read ResultMinor: {e}"
                                            ))
                                        })?
                                        .to_string(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    depth -= 1;
                    if e.name().as_ref() == b"Result" {
                        in_result = false;
                    }
                }
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

        if let Some(major) = result_major {
            if major.contains("error") {
                return Err(AuthError::card_communication_error(format!(
                    "SOAP response indicates error: major={major}, minor={result_minor:?}"
                )));
            }
        }

        let output = if is_type_a {
            if ef_card_security.is_empty() || authentication_token.is_empty() || nonce.is_empty() {
                return Err(AuthError::card_communication_error(
                    "Missing required EAC2 Type A output fields in response",
                ));
            }
            EAC2OutputType::A {
                ef_card_security,
                authentication_token,
                nonce,
            }
        } else {
            if challenge.is_empty() {
                return Err(AuthError::card_communication_error(
                    "Missing required EAC2 Type B challenge in response",
                ));
            }
            EAC2OutputType::B { challenge }
        };

        serde_json::to_string(&output).map_err(|e| {
            AuthError::card_communication_error(format!("Failed to serialize EAC2 output: {e}"))
        })
    }
}
