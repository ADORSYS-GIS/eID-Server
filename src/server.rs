use std::fs::File;
use std::io::{BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::eid::get_server_info::handler::get_server_info;
use crate::web::handlers;
use crate::web::handlers::refresh::refresh_handler;
use crate::web::handlers::sal::paos::paos_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use color_eyre::eyre::{Context, Result, eyre};
use handlers::did_auth::did_authenticate;
use handlers::health::health_check;
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Debug, Clone)]
pub struct AppServerConfig {
    pub host: String,
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
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
    async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<RustlsConfig> {
        tracing::debug!("Loading TLS certificate from: {}", cert_path);
        // Read certificate file
        let mut cert_file = File::open(Path::new(cert_path))
            .map_err(|e| eyre!("Failed to open cert file: {}", e))
            .context("Opening certificate file")?;
        let mut certs_data = Vec::new();
        cert_file
            .read_to_end(&mut certs_data)
            .map_err(|e| eyre!("Failed to read cert file: {}", e))
            .context("Reading certificate file")?;

        if certs_data.is_empty() {
            return Err(eyre!("No certificates found in cert file"))
                .context("Certificate validation");
        }

        let certs: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut BufReader::new(certs_data.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| eyre!("Failed to parse certificates: {}", e))
                .context("Parsing certificates")?
                .into_iter()
                .map(CertificateDer::from)
                .collect();

        tracing::debug!("Loaded {} certificate(s)", certs.len());

        tracing::debug!("Loading private key from: {}", key_path);
        let mut key_file = File::open(Path::new(key_path))
            .map_err(|e| eyre!("Failed to open key file: {}", e))
            .context("Opening private key file")?;
        let mut key_data = Vec::new();
        key_file
            .read_to_end(&mut key_data)
            .map_err(|e| eyre!("Failed to read key file: {}", e))
            .context("Reading private key file")?;

        if key_data.is_empty() {
            return Err(eyre!("No private key found in key file")).context("Private key not found");
        }

        let key = rustls_pemfile::private_key(&mut BufReader::new(key_data.as_slice()))
            .map_err(|e| eyre!("Failed to parse private key: {}", e))
            .context("Parsing private key")?
            .ok_or_else(|| eyre!("No private key found"))?;
        let key = PrivateKeyDer::from(key);

        // Create a CertifiedKey for certificate-based TLS
        let signing_key = provider::sign::any_supported_type(&key)
            .map_err(|e| eyre!("Failed to create signing key: {}", e))?;
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));

        // Configure rustls ServerConfig with certificate-based TLS
        let cert_resolver = Arc::new(CertResolver::new(certified_key.clone()));

        // Create provider and server config
        let provider = provider::default_provider();
        let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .map_err(|e| eyre!("Failed to set protocol versions: {}", e))?
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);

        let tls_config = RustlsConfig::from_config(Arc::new(server_config));

        tracing::info!("TLS configuration loaded with certificate support");
        tracing::info!("Using default secure cipher suites and protocol versions");

        Ok(tls_config)
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

        let tls_config = Self::load_tls_config(cert_path, key_path)
            .await
            .context("Loading TLS configuration")?;

        tracing::info!("Server listening on https://{}:{}", config.host, bound_port);
        tracing::info!("Using certificate: {}", cert_path);
        tracing::info!("Using private key: {}", key_path);
        tracing::info!("TLS configuration: Certificate-based TLS with default secure settings");

        let server = axum_server::from_tcp_rustls(listener, tls_config)
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
