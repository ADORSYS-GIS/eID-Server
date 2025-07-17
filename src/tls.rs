mod cert_utils;
mod errors;
mod psk;

pub use cert_utils::*;
pub use errors::TlsError;
pub use psk::{PskStore, PskStoreError};

use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::ssl::{
    ClientHelloResponse, SslAcceptor, SslAcceptorBuilder, SslContext, SslMethod,
    SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use openssl::x509::X509;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{debug, instrument, trace, warn};

// TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095 (149)
// TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094 (148)
const PSK_CIPHER_IDS: &[u16] = &[0x0095, 0x0094];
const PSK_CIPHER_SUITES: &[&str] = &["RSA-PSK-AES256-CBC-SHA", "RSA-PSK-AES128-CBC-SHA"];
const SESSION_ID: &[u8] = b"eid-server-tls-session-id";

struct PskTlsConfig {
    psk_store: Arc<dyn PskStore>,
    cipher_suites: Vec<String>,
}

struct Inner {
    cert_chain: Vec<u8>,
    private_key: Vec<u8>,
    intermediate_certs: Mutex<Option<Vec<u8>>>,
    ca_certs: Mutex<Option<Vec<Vec<u8>>>>,
    psk_config: Mutex<Option<PskTlsConfig>>,
}

/// Configuration for the TLS server.
#[derive(Clone)]
pub struct TlsConfig {
    inner: Arc<Inner>,
}

impl TlsConfig {
    /// Creates a new TLS configuration.
    ///
    /// # Arguments
    ///
    /// * `cert_chain_pem` - Server certificate chain in PEM format.
    /// * `private_key_pem` - Server private key in PEM format.
    /// * `ca_certs_pem` - CA certificates in PEM format (required for client authentication).
    pub fn new(cert_chain_pem: impl Into<Vec<u8>>, private_key_pem: impl Into<Vec<u8>>) -> Self {
        debug!("Creating new TLS configuration");
        Self {
            inner: Arc::new(Inner {
                psk_config: Mutex::new(None),
                cert_chain: cert_chain_pem.into(),
                private_key: private_key_pem.into(),
                intermediate_certs: Mutex::new(None),
                ca_certs: Mutex::new(None),
            }),
        }
    }

    /// Enable client authentication by providing root CA certificates in PEM format.
    pub fn with_client_auth(
        self,
        ca_certs_pem: impl Into<Vec<Vec<u8>>>,
        intermediate_certs_pem: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        debug!("Enabling client authentication with CA certificates");
        *self.inner.ca_certs.lock() = Some(ca_certs_pem.into());
        *self.inner.intermediate_certs.lock() = intermediate_certs_pem.map(Into::into);
        self
    }

    /// Add PSK support to the TLS configuration by providing a PSK store.
    pub fn with_psk(self, psk_store: impl PskStore + 'static) -> Self {
        debug!("Adding PSK support to TLS configuration");
        *self.inner.psk_config.lock() = Some(PskTlsConfig {
            psk_store: Arc::new(psk_store),
            cipher_suites: PSK_CIPHER_SUITES.iter().map(|s| s.to_string()).collect(),
        });
        self
    }

    /// Build the TLS acceptor from the configuration.
    #[instrument(skip(self))]
    pub fn build_acceptor(&self) -> Result<SslAcceptor, TlsError> {
        // Create a base acceptor builder
        let mut builder = self.create_base_acceptor_builder()?;

        // Create the PSK context
        let psk_ctx = self.create_psk_ssl_context()?;

        let mtls_required = self.inner.ca_certs.lock().is_some();

        builder.set_client_hello_callback(move |ssl, _alert| {
            trace!("ClientHello received, analyzing cipher suites...");

            // Check if client offers PSK cipher suites
            if let Some(cipher_list) = ssl.client_hello_ciphers() {
                let cipher_ids: Vec<u16> = cipher_list
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                    .collect();

                debug!("Client offered cipher IDs: {:?}", cipher_ids);

                // Check if any PSK cipher suites are offered
                let has_psk_cipher = cipher_ids.iter().any(|&id| PSK_CIPHER_IDS.contains(&id));

                if has_psk_cipher {
                    debug!("Client offers PSK cipher suites, switching to PSK context");
                    ssl.set_ssl_context(&psk_ctx)?;
                } else {
                    debug!("Client offers regular TLS cipher suites, using standard TLS context");
                    if mtls_required {
                        ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                    } else {
                        ssl.set_verify(SslVerifyMode::NONE);
                    }
                }
            } else {
                warn!("No cipher list available from client, aborting");
                return Err(ErrorStack::get());
            }

            Ok(ClientHelloResponse::SUCCESS)
        });

        Ok(builder.build())
    }

    #[instrument(skip(self))]
    fn create_base_acceptor_builder(&self) -> Result<SslAcceptorBuilder, ErrorStack> {
        // Create new acceptor with reasonable defaults
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;

        // Load server certificate chain and private key
        trace!("Loading server certificate chain from PEM...");
        let cert = X509::from_pem(&self.inner.cert_chain)?;
        trace!("Loading server private key from PEM...");
        let key = PKey::private_key_from_pem(&self.inner.private_key)?;

        // Configure server certificate and private key
        builder.set_certificate(&cert)?;
        builder.set_private_key(&key)?;
        debug!("Set server certificate and private key");

        // Add intermediate certs if needed
        if let Some(intermediate_certs) = self.inner.intermediate_certs.lock().as_ref() {
            debug!("Adding intermediate certificates to chain");
            let intermediate_certs = X509::stack_from_pem(intermediate_certs)?;
            for intermediate_cert in intermediate_certs {
                builder.add_extra_chain_cert(intermediate_cert)?;
            }
        }

        // Load trusted CA certificates for client cert verification
        if let Some(ca_certs) = self.inner.ca_certs.lock().as_ref() {
            debug!("Loading trusted CA certificates for client verification...");
            for ca_cert in ca_certs {
                let ca_cert = X509::from_pem(ca_cert)?;
                let store = builder.cert_store_mut();
                store.add_cert(ca_cert)?;
            }
        }

        // Enable session resumption
        // TR-03130-1 §2.3.2
        builder.set_session_cache_mode(
            SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL_LOOKUP,
        );
        builder.set_session_id_context(SESSION_ID)?;
        debug!("Enabled session resumption with server-side caching");

        if let Some(psk_config) = self.inner.psk_config.lock().as_ref() {
            // Set PSK server callback
            let psk_store = psk_config.psk_store.clone();
            builder.set_psk_server_callback(move |_ssl, identity, psk_buf| {
                debug!("PSK server callback invoked");
                if let Some(psk_identity) = identity {
                    let psk_identity_str = String::from_utf8_lossy(psk_identity);
                    debug!(identity = %psk_identity_str, "PSK identity provided");

                    match psk_store.get_psk(psk_identity) {
                        Ok(Some(psk)) => {
                            if psk_buf.len() >= psk.len() {
                                debug!("PSK found for identity, proceeding with PSK handshake");
                                psk_buf[..psk.len()].copy_from_slice(&psk);
                                return Ok(psk.len());
                            } else {
                                warn!(
                                    psk_len = psk.len(),
                                    buf_len = psk_buf.len(),
                                    "PSK buffer too small"
                                );
                            }
                        }
                        Ok(None) => {
                            warn!(identity = %psk_identity_str, "PSK not found for identity");
                        }
                        Err(e) => {
                            warn!(error = ?e, "Error retrieving PSK for identity");
                        }
                    }
                } else {
                    debug!("No PSK identity provided by client");
                }

                // Fallback for failed PSK
                debug!("PSK handshake failed, returning 0");
                Ok(0)
            });
        }

        Ok(builder)
    }

    #[instrument(skip(self))]
    fn create_psk_ssl_context(&self) -> Result<SslContext, ErrorStack> {
        let mut builder = self.create_base_acceptor_builder()?;

        // Force TLS 1.2 for PSK
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

        builder.set_verify(SslVerifyMode::NONE);

        if let Some(psk_config) = self.inner.psk_config.lock().as_ref() {
            let psk_cipher_suites = psk_config.cipher_suites.join(":");
            builder.set_cipher_list(&psk_cipher_suites)?;
            debug!("PSK context: Set PSK cipher suites: {psk_cipher_suites}");

            return Ok(builder.build().into_context());
        }

        Err(ErrorStack::get())
    }
}
