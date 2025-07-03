use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::eid::get_server_info::handler::get_server_info;
use crate::web::handlers;
use crate::web::handlers::refresh::refresh_handler;
use crate::web::handlers::sal::paos::paos_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use color_eyre::eyre::{Context, Result, eyre};
use handlers::did_auth::did_authenticate;
use handlers::health::health_check;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslOptions, SslVerifyMode};
use rustls::lock::Mutex;
use rustls::server::{ClientHello, ResolvesServerCert};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use axum_server::tls_openssl::OpenSSLConfig;

// Global PSK store
static PSK_STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

fn get_psk_store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    PSK_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct AppServerConfig {
    pub host: String,
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub psk_enabled: bool, // Add PSK enabled flag
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
}

#[derive(Debug)]
struct CertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl CertResolver {
    fn new(certified_key: Arc<rustls::sign::CertifiedKey>) -> Self {
        CertResolver { certified_key }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        tracing::debug!("Using certificate-based TLS");
        Some(self.certified_key.clone())
    }
}

pub struct Server<S: EIDService + EidService + DIDAuthenticate + Clone + Send + Sync + 'static> {
    router: Router,
    state: AppState<S>,
}

impl<S: EIDService + EidService + DIDAuthenticate + Clone + Send + Sync + 'static> Server<S> {
    /// Creates a new HTTPS server with certificate-based TLS configuration.
    pub async fn new(eid_service: S, _config: AppServerConfig) -> Result<Self> {
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &'_ axum::extract::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = %request.method(), uri)
            });

        let cors_layer = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        let eid_service = Arc::new(eid_service);
        let state = AppState {
            use_id: eid_service.clone(),
            eid_service,
        };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(handlers::useid::use_id_handler))
            .route("/eIDService/useID", get(handlers::useid::use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .route("/did-authenticate", post(did_authenticate))
            .route("/refresh", get(refresh_handler))
            .layer(cors_layer)
            .route("/eIDService/paos", post(paos_handler))
            .layer(trace_layer)
            .with_state(state.clone());

        Ok(Self { router, state })
    }

    /// Loads TLS certificates for certificate-based TLS
    async fn load_tls_config(
        cert_path: &str,
        key_path: &str,
        psk_enabled: bool,
    ) -> Result<OpenSSLConfig> {
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls())?;

        // Configure certificate-based TLS
        acceptor.set_private_key_file(key_path, SslFiletype::PEM)?;
        acceptor.set_certificate_chain_file(cert_path)?;

        if psk_enabled {
            acceptor.set_psk_server_callback(|_ssl, identity, secret| {
                let identity_str = identity
                    .and_then(|id| String::from_utf8(id.to_vec()).ok())
                    .unwrap_or_default();

                tracing::debug!("PSK identity requested: {}", identity_str);

                if let Some(psk) = get_psk_store().lock().unwrap().get(&identity_str) {
                    if secret.len() < psk.len() {
                        return Ok(0); // Return Result with Ok
                    }
                    secret[..psk.len()].copy_from_slice(psk);
                    Ok(psk.len()) // Return Result with Ok
                } else {
                    tracing::warn!("No PSK found for identity: {}", identity_str);
                    Ok(0) // Return Result with Ok
                }
            });

            // Configure PSK cipher suites
            acceptor.set_cipher_list(
                "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384"
            )?;

            // Enable PSK key exchange
            acceptor.set_options(SslOptions::NO_TICKET);
        }

        // Common TLS settings
        acceptor.set_verify(SslVerifyMode::NONE);
        acceptor.set_options(
            SslOptions::NO_COMPRESSION | SslOptions::SINGLE_ECDH_USE | SslOptions::SINGLE_DH_USE,
        );

        // Build and convert to axum_server's OpenSSLConfig
        Ok(OpenSSLConfig::from_acceptor(Arc::new(acceptor.build())))
    }

    /// Validates certificate chain and logs certificate information
    fn validate_certificate_chain(cert_path: &str) -> Result<()> {
        tracing::info!("Validating certificate chain...");

        let cert_file = File::open(Path::new(cert_path))
            .map_err(|e| eyre!("Failed to open cert file for validation: {}", e))
            .context("Opening certificate file for validation")?;

        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| eyre!("Error reading certs for validation: {}", e))
            .context("Parsing certificate for validation")?
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();

        if certs.is_empty() {
            return Err(eyre!("No certificates found for validation"));
        }

        tracing::info!("Certificate chain validation successful");
        tracing::info!("Found {} certificate(s) in chain", certs.len());

        if let Some(cert) = certs.first() {
            tracing::info!("Leaf certificate size: {} bytes", cert.len());
        }

        Ok(())
    }

    /// Runs the HTTPS server with certificate-based TLS and returns the bound port.
    pub async fn run_with_port(
        self,
        config: AppServerConfig,
    ) -> Result<(u16, tokio::task::JoinHandle<()>)> {
        let addr = format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(&addr).context("Binding TCP listener")?;
        listener
            .set_nonblocking(true)
            .context("Setting non-blocking mode")?;
        let bound_port = listener
            .local_addr()
            .context("Getting local address")?
            .port();

        let cert_path = config
            .cert_path
            .as_deref()
            .unwrap_or("certss/localhost.crt");
        let key_path = config.key_path.as_deref().unwrap_or("certss/localhost.key");

        // Validate certificate chain before starting server
        Self::validate_certificate_chain(cert_path)
            .context("Certificate chain validation failed")?;

        let tls_config = Self::load_tls_config(cert_path, key_path, config.psk_enabled)
            .await
            .context("Loading TLS configuration")?;

        tracing::info!("Server listening on https://{}:{}", config.host, bound_port);
        tracing::info!("Using certificate: {}", cert_path);
        tracing::info!("Using private key: {}", key_path);
        tracing::info!("TLS configuration: Certificate-based TLS with default secure settings");

        let server = axum_server::Server::from_tcp(listener)
            .openssl(tls_config)
            .serve(self.router.into_make_service());

        let handle = tokio::spawn(async move {
            if let Err(e) = server.await {
                tracing::error!("Server error: {:?}", e);
            }
        });

        Ok((bound_port, handle))
    }

    /// Runs the HTTPS server with certificate-based TLS.
    pub async fn run(self, config: AppServerConfig) -> Result<()> {
        let (port, handle) = self.run_with_port(config).await?;
        tracing::info!("Server running on port {} with certificate-based TLS", port);
        handle
            .await
            .map_err(|e| eyre!("Server task failed: {:?}", e))
            .context("Running server task")?;
        Ok(())
    }
}
