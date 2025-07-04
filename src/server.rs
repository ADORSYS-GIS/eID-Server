//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use crate::eid::get_server_info::handler::get_server_info;
use crate::server::handlers::refresh::refresh_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use color_eyre::eyre::{Result, eyre};
use handlers::did_auth::did_authenticate;
use handlers::health::health_check;
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};

#[derive(Debug, Clone)]
pub struct AppServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
}

pub struct Server {
    router: Router,
}

impl Server {
    /// Loads TLS certificates from key.pem and cert.pem files.
    fn load_tls_config() -> Result<RustlsConfig> {
        // Install the default CryptoProvider (ring)
        default_provider()
            .install_default()
            .map_err(|_| eyre!("Failed to install CryptoProvider"))?;

        let cert_path = "certss/cert.pem";
        let key_path = "certss/key.pem";

        let cert_file = File::open(Path::new(cert_path))
            .map_err(|e| eyre!("Failed to open cert file: {}", e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| eyre!("Error reading certs: {e}"))?
            .into_iter()
            .collect();

        let key_file =
            File::open(Path::new(key_path)).map_err(|e| eyre!("Failed to open key file: {}", e))?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| eyre!("Error reading private key: {}", e))?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();

        if keys.is_empty() {
            return Err(eyre!("No private key found in key.pem"));
        }

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|e| eyre!("Failed to build TLS config: {}", e))?;

        Ok(RustlsConfig::from_config(Arc::new(server_config)))
    }

    /// Creates a new HTTPS server.
    pub async fn new(
        eid_service: impl EIDService + EidService + DIDAuthenticate,
        _config: AppServerConfig,
    ) -> Result<Self> {
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
            .layer(trace_layer)
            .with_state(state);

        Ok(Self { router })
    }

    /// Runs the HTTPS server and returns the bound port.
    pub async fn run_with_port(
        self,
        config: AppServerConfig,
    ) -> Result<(u16, tokio::task::JoinHandle<()>)> {
        let addr = format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        let bound_port = listener.local_addr()?.port();

        let tls_config = Self::load_tls_config()?;

        tracing::debug!("Server listening on https://{}:{}", config.host, bound_port);

        let server = axum_server::from_tcp_rustls(listener, tls_config)
            .serve(self.router.into_make_service());

        let handle = tokio::spawn(async move {
            server.await.expect("Failed to run server");
        });

        Ok((bound_port, handle))
    }

    /// Runs the HTTPS server.
    pub async fn run(self, config: AppServerConfig) -> Result<()> {
        let (port, handle) = self.run_with_port(config).await?;
        tracing::info!("Server running on port {}", port);
        handle.await?;
        Ok(())
    }
}
