mod cert_utils;
mod errors;
mod psk;
mod session;

pub use cert_utils::*;
pub use errors::TlsError;
pub use psk::{PskStore, PskStoreError};
pub use session::{InMemorySessionStore, RedisSessionStore, SessionStore, SessionStoreError};

use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::ssl::{
    ClientHelloResponse, SslAcceptor, SslAcceptorBuilder, SslContext, SslMethod, SslSession,
    SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use openssl::x509::X509;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::task;
use tracing::{debug, error, instrument, trace, warn};

// RSA PSK Cipher suites
// TLS_RSA_PSK_WITH_AES_256_CBC_SHA = {0x00,0x95}
// TLS_RSA_PSK_WITH_AES_128_CBC_SHA = {0x00,0x94}
// TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = {0x00,0xAD}
// TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = {0x00,0xAC}
const PSK_CIPHER_IDS: &[u16] = &[0x0095, 0x0094, 0x00AD, 0x00AC];
const PSK_CIPHER_SUITES: &[&str] = &[
    "RSA-PSK-AES256-CBC-SHA",
    "RSA-PSK-AES128-CBC-SHA",
    "RSA-PSK-AES256-GCM-SHA384",
    "RSA-PSK-AES128-GCM-SHA256",
];
const SESSION_ID: &[u8] = b"eid-server-tls-session-id";

struct TlsPskConfig {
    psk_store: Arc<dyn PskStore>,
    cipher_suites: Vec<String>,
}

struct Inner {
    cert_chain: Vec<u8>,
    private_key: Vec<u8>,
    intermediate_certs: Option<Vec<u8>>,
    ca_certs: Option<Vec<Vec<u8>>>,
    psk_config: Option<TlsPskConfig>,
    is_mtls: bool,
    session_store: Option<Arc<dyn SessionStore>>,
}

/// Configuration for the TLS server.
pub struct TlsConfig {
    inner: Inner,
}

impl TlsConfig {
    /// Creates a new TLS configuration.
    ///
    /// # Arguments
    ///
    /// * `cert_chain_pem` - Server certificate chain in PEM format.
    /// * `private_key_pem` - Server private key in PEM format.
    pub fn new(cert_chain_pem: impl Into<Vec<u8>>, private_key_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Inner {
                psk_config: None,
                cert_chain: cert_chain_pem.into(),
                private_key: private_key_pem.into(),
                intermediate_certs: None,
                ca_certs: None,
                is_mtls: false,
                session_store: None,
            },
        }
    }

    /// Enable client authentication by providing root CA certificates in PEM format.
    /// Optional intermediate certificates can also be provided.
    pub fn with_client_auth(
        mut self,
        ca_certs_pem: impl Into<Vec<Vec<u8>>>,
        intermediate_certs_pem: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        debug!("Enabling client authentication with CA certificates");
        self.inner.ca_certs = Some(ca_certs_pem.into());
        self.inner.intermediate_certs = intermediate_certs_pem.map(Into::into);
        self.inner.is_mtls = true;
        self
    }

    /// Add PSK support to the TLS configuration by providing a PSK store.
    pub fn with_psk(mut self, psk_store: impl PskStore + 'static) -> Self {
        debug!("Adding PSK support to TLS configuration");
        self.inner.psk_config = Some(TlsPskConfig {
            psk_store: Arc::new(psk_store),
            cipher_suites: PSK_CIPHER_SUITES.iter().map(|s| s.to_string()).collect(),
        });
        self
    }

    /// Add session store support for centralized session caching.
    pub fn with_session_store(mut self, session_store: impl SessionStore + 'static) -> Self {
        debug!("Adding session store support to TLS configuration");
        self.inner.session_store = Some(Arc::new(session_store));
        self
    }

    /// Build the TLS acceptor from the configuration.
    #[instrument(skip(self))]
    pub fn build_acceptor(&self) -> Result<SslAcceptor, TlsError> {
        // Create a base acceptor builder
        let mut builder = self.create_base_acceptor_builder()?;

        // Create the PSK context only if PSK is configured
        let psk_ctx = self
            .inner
            .psk_config
            .as_ref()
            .map(|_| self.create_psk_ssl_context())
            .transpose()?;

        // Configure session callbacks if session store is available
        if let Some(session_store) = &self.inner.session_store {
            self.setup_session_callbacks(&mut builder, session_store)?;
        }

        // Check if client authentication is required
        let mtls_required = self.inner.is_mtls;

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
                    if let Some(psk_ctx) = &psk_ctx {
                        debug!("Client offers PSK cipher suites, switching to PSK context");
                        ssl.set_ssl_context(psk_ctx)?;
                    } else {
                        warn!("Client offers PSK cipher suites, but no PSK context is configured");
                    }
                } else {
                    debug!("Client offers regular TLS cipher suites, using standard TLS context");
                    if mtls_required {
                        // Enable client authentication
                        ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                    } else {
                        ssl.set_verify(SslVerifyMode::NONE);
                    }
                }
            } else {
                warn!("No cipher list available from client, aborting handshake");
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

        // Load trusted CA certificates for client authentication
        if let Some(ca_certs) = &self.inner.ca_certs {
            debug!("Loading trusted CA certificates for client authentication...");
            for ca_cert in ca_certs {
                let ca_cert = X509::from_pem(ca_cert)?;
                let store = builder.cert_store_mut();
                store.add_cert(ca_cert)?;
            }
        }

        // Add intermediate certs if needed
        if let Some(intermediate_certs) = &self.inner.intermediate_certs {
            debug!("Adding intermediate certificates to chain");
            let intermediate_certs = X509::stack_from_pem(intermediate_certs)?;
            for intermediate_cert in intermediate_certs {
                builder.add_extra_chain_cert(intermediate_cert)?;
            }
        }

        if self.inner.session_store.is_none() {
            // Enable default session resumption only if no external store is configured
            builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
            debug!("Enabled default session resumption with server-side caching");
        }

        if let Some(psk_config) = &self.inner.psk_config {
            // Set PSK server callback
            let psk_store = psk_config.psk_store.clone();
            builder.set_psk_server_callback(move |_ssl, identity, psk_buf| {
                debug!("PSK server callback invoked");
                if let Some(psk_identity) = identity {
                    let psk_identity_str = String::from_utf8_lossy(psk_identity);
                    debug!(identity = %psk_identity_str, "PSK identity provided");

                    let result = task::block_in_place(|| {
                        Handle::current().block_on(psk_store.get_psk(psk_identity))
                    });

                    match result {
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
                            error!(error = ?e, "Error retrieving PSK for identity");
                        }
                    }
                } else {
                    warn!("No PSK identity provided by client");
                }

                // Fallback for failed PSK
                error!("PSK handshake failed, returning 0");
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

        if let Some(psk_config) = &self.inner.psk_config {
            let psk_cipher_suites = psk_config.cipher_suites.join(":");
            builder.set_cipher_list(&psk_cipher_suites)?;
            debug!("PSK context: Set PSK cipher suites: {psk_cipher_suites}");

            return Ok(builder.build().into_context());
        }

        Err(ErrorStack::get())
    }

    #[instrument(skip(self, builder, session_store))]
    fn setup_session_callbacks(
        &self,
        builder: &mut SslAcceptorBuilder,
        session_store: &Arc<dyn SessionStore>,
    ) -> Result<(), TlsError> {
        debug!("Setting up session store callbacks");

        // Configure session caching mode for external storage
        builder
            .set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
        builder.set_session_id_context(SESSION_ID)?;

        // Clone store for callbacks
        let store_new = session_store.clone();
        let store_get = session_store.clone();
        let store_remove = session_store.clone();

        // Set new session callback that is called when a new session is created
        builder.set_new_session_callback(move |_ssl, session| {
            let store = store_new.clone();
            Handle::current().spawn(async move {
                let session_id = session.id();
                let session_str = hex::encode(session_id);
                let session_data = match session.to_der() {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to serialize session data for session {session_str}: {e}");
                        return;
                    }
                };

                match store.store_session(session_id, &session_data).await {
                    Ok(_) => debug!("Session {session_str} stored successfully"),
                    Err(e) => error!("Failed to store session {session_str}: {e}"),
                }
            });
        });

        // Set get session callback that is called when a client tries to resume a session
        unsafe {
            builder.set_get_session_callback(move |_ssl, session_id| {
                let store = store_get.clone();
                let session_str = hex::encode(session_id);

                let result = task::block_in_place(|| {
                    Handle::current().block_on(async move { store.get_session(session_id).await })
                });

                match result {
                    Ok(Some(session_data)) => match SslSession::from_der(&session_data) {
                        Ok(session) => {
                            debug!("Session {session_str} retrieved successfully");
                            Some(session)
                        }
                        Err(e) => {
                            error!("Failed to deserialize session {session_str}: {e}");
                            None
                        }
                    },
                    Ok(None) => {
                        debug!("Session {session_str} not found in store");
                        None
                    }
                    Err(e) => {
                        error!("Failed to retrieve session {session_str}: {e}");
                        None
                    }
                }
            });
        }

        // Set remove session callback that is called when a session is invalidated
        builder.set_remove_session_callback(move |_ctx, session| {
            let store = store_remove.clone();
            let session_id = session.id().to_vec();
            let session_str = hex::encode(&session_id);

            Handle::current().spawn(async move {
                match store.remove_session(&session_id).await {
                    Ok(_) => debug!("Session {session_str} removed successfully"),
                    Err(e) => error!("Failed to remove session {session_str}: {e}"),
                }
            });
        });

        Ok(())
    }
}
