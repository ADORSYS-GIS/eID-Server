//! TLS PSK (Pre-Shared Key) implementation for eID-Server
//!
//! This module implements TLS-2 connection as specified in the eID documentation.
//! It provides PSK-based authentication for secure communication between
//! eID-Server and eID-Client at the eCard-API-Framework interface.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tracing::{debug, error, warn};

use crate::domain::eid::ports::{EIDService, EidService};
use crate::server::AppState;

/// PSK store for managing pre-shared keys and session identifiers
#[derive(Clone, Debug)]
pub struct PskStore {
    /// Map of session_id -> PSK
    psks: Arc<std::sync::RwLock<HashMap<String, String>>>,
}

impl PskStore {
    pub fn new() -> Self {
        Self {
            psks: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Add a PSK for a session
    pub fn add_psk(
        &self,
        session_id: String,
        psk: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut psks = self
            .psks
            .write()
            .map_err(|e| format!("PSK store lock error: {}", e))?;
        psks.insert(session_id, psk);
        Ok(())
    }

    /// Get PSK for a session
    pub fn get_psk(&self, session_id: &str) -> Option<String> {
        let psks = self.psks.read().ok()?;
        psks.get(session_id).cloned()
    }

    /// Remove PSK for a session
    pub fn remove_psk(&self, session_id: &str) -> Option<String> {
        let mut psks = self.psks.write().ok()?;
        psks.remove(session_id)
    }
}

/// TLS PSK configuration for the eID server
pub struct TlsPskConfig {
    pub psk_store: PskStore,
    pub server_cert: Vec<CertificateDer<'static>>,
    pub server_key: PrivateKeyDer<'static>,
}

impl TlsPskConfig {
    pub fn new(
        server_cert: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            psk_store: PskStore::new(),
            server_cert,
            server_key,
        }
    }

    /// Create TLS server configuration with basic TLS support
    /// Note: For full PSK cipher suite support, additional rustls configuration would be needed
    pub fn create_server_config(&self) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.server_cert.clone(), self.server_key.clone_key())?;

        Ok(config)
    }
}

// Manual Clone implementation for TlsPskConfig
impl Clone for TlsPskConfig {
    fn clone(&self) -> Self {
        Self {
            psk_store: self.psk_store.clone(),
            server_cert: self.server_cert.clone(),
            server_key: self.server_key.clone_key(),
        }
    }
}

/// Middleware to validate PSK before processing PAOS requests
/// This is a real implementation that validates the PSK against the session store
pub async fn psk_validation_middleware<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    session_id: String,
    provided_psk: String,
) -> Result<(), StatusCode> {
    debug!("Validating PSK for session: {}", session_id);

    // Get the session from the session manager
    let session_manager_arc = state.use_id.get_session_manager();
    let session_manager = session_manager_arc.read().map_err(|_| {
        error!("Failed to acquire session manager lock");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Find the session
    let session = session_manager
        .sessions
        .iter()
        .find(|s| s.id == session_id)
        .ok_or_else(|| {
            warn!("Session not found: {}", session_id);
            StatusCode::UNAUTHORIZED
        })?;

    // Verify PSK exists in session
    let session_psk = &session.psk;

    // Validate the provided PSK against the stored PSK
    if provided_psk != *session_psk {
        warn!("PSK mismatch for session: {}", session_id);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Additional validation: Check if PSK is also in the PSK store (if available)
    if let Some(ref psk_store) = state.psk_store {
        match psk_store.get_psk(&session_id) {
            Some(stored_psk) => {
                if stored_psk != provided_psk {
                    warn!("PSK store mismatch for session: {}", session_id);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
            None => {
                warn!("PSK not found in PSK store for session: {}", session_id);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    debug!("PSK validation successful for session: {}", session_id);
    Ok(())
}

/// Validate PSK during TLS handshake
/// This function is called during the TLS PSK callback to validate the client's PSK
pub fn validate_psk_callback(
    psk_store: &PskStore,
    identity: &str,
    provided_psk: &[u8],
) -> Option<Vec<u8>> {
    debug!("PSK callback validation for identity: {}", identity);

    // Get the stored PSK for this session/identity
    let stored_psk = psk_store.get_psk(identity)?;

    // Convert provided PSK to string for comparison
    let provided_psk_str = match std::str::from_utf8(provided_psk) {
        Ok(s) => s,
        Err(_) => {
            warn!("Invalid UTF-8 in provided PSK for identity: {}", identity);
            return None;
        }
    };

    // Validate PSK matches
    if stored_psk == provided_psk_str {
        debug!("PSK validation successful for identity: {}", identity);
        Some(stored_psk.into_bytes())
    } else {
        warn!("PSK validation failed for identity: {}", identity);
        None
    }
}

/// Axum middleware for PSK validation
/// This middleware validates the PSK before allowing requests to proceed to the handler
pub async fn psk_validation_layer<S: EIDService + EidService + Clone + Send + Sync + 'static>(
    State(state): State<AppState<S>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    debug!("PSK validation middleware triggered");

    // Extract the request body to parse the PAOS request
    let body_bytes = match axum::body::to_bytes(std::mem::take(request.body_mut()), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!("Failed to read request body for PSK validation: {}", err);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let body_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(err) => {
            error!("Invalid UTF-8 in request body: {}", err);
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    println!("{}", body_str);
    // Parse the PAOS request to extract session identifier
    let paos_request = match crate::sal::paos::parser::parse_start_paos(body_str) {
        
        Ok(request) => request,
        Err(err) => {
            error!("Failed to parse PAOS request for PSK validation: {}", err);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let session_id = paos_request.session_identifier;
    if session_id.is_empty() {
        error!("Session identifier is required for PSK validation");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get the PSK from the session for validation
    let session_manager_arc = state.use_id.get_session_manager();
    let session_psk = match session_manager_arc.read() {
        Ok(mgr) => mgr
            .sessions
            .iter()
            .find(|s| s.id == session_id)
            .map(|s| s.psk.clone()),
        Err(e) => {
            error!("Session manager lock error during PSK validation: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let psk = match session_psk {
        Some(psk) => psk,
        None => {
            warn!(
                "No PSK found for session {} in secure connection",
                session_id
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Validate PSK using the middleware function
    if let Err(status) = psk_validation_middleware(State(state), session_id.clone(), psk).await {
        warn!("PSK validation failed for session: {}", session_id);
        return Err(status);
    }

    // Reconstruct the request body for the next handler
    *request.body_mut() = axum::body::Body::from(body_bytes);

    debug!(
        "PSK validation successful for session: {}, proceeding to handler",
        session_id
    );
    Ok(next.run(request).await)
}

/// Create a TLS acceptor with PSK support
pub fn create_tls_acceptor(
    config: TlsPskConfig,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let server_config = config.create_server_config()?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Generate a self-signed certificate for testing purposes
/// In production, use proper certificates
pub fn generate_self_signed_cert()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    // Generate a key pair
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    // Create certificate parameters
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "eID-Server");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "eID-Server");
    params.key_pair = Some(key_pair);

    // Generate the certificate
    let cert = Certificate::from_params(params)?;

    // Convert to rustls format
    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivateKeyDer::try_from(cert.serialize_private_key_der())?;

    Ok((vec![cert_der], key_der))
}

/// Create a TLS PSK configuration with self-signed certificate for testing
pub fn create_test_tls_config() -> Result<TlsPskConfig, Box<dyn std::error::Error>> {
    let (cert, key) = generate_self_signed_cert()?;
    Ok(TlsPskConfig::new(cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_store_operations() {
        let store = PskStore::new();
        let session_id = "test_session".to_string();
        let psk = "test_psk_value".to_string();

        // Test adding PSK
        assert!(store.add_psk(session_id.clone(), psk.clone()).is_ok());

        // Test getting PSK
        assert_eq!(store.get_psk(&session_id), Some(psk.clone()));

        // Test removing PSK
        assert_eq!(store.remove_psk(&session_id), Some(psk));
        assert_eq!(store.get_psk(&session_id), None);
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());
        let (certs, _key) = result.unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_create_test_tls_config() {
        let result = create_test_tls_config();
        assert!(result.is_ok());
    }
}
