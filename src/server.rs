//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener as StdTcpListener;
use std::path::Path;
use std::sync::Arc;

use crate::config::TlsConfig;
use crate::eid::get_server_info::handler::get_server_info;
use axum::{http::Method, routing::get, routing::post, Router};
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
    pub eid_service: Arc<S>,
}

pub struct Server {
    router: Router,
    listener: Option<tokio::net::TcpListener>,
    std_listener: Option<StdTcpListener>,
    tls_config: Option<RustlsConfig>,
}

impl Server {
    /// Loads TLS certificates from key.pem and cert.pem files as a fallback.
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

    /// Creates a new HTTP/HTTPS server.
    pub async fn new<S: EIDService + EidService + DIDAuthenticate>(
        eid_service: S,
        config: AppServerConfig,
        tls_config: Option<TlsConfig>,
    ) -> Result<Self> {
        // Initialize the tracing layer to log HTTP requests.
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = %request.method(), uri)
            });

        let cors_layer = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods(vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        let eid_service = Arc::new(eid_service);
        let state = AppState { eid_service };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(handlers::useid::use_id_handler))
            .route("/eIDService/useID", get(handlers::useid::use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .route("/did-authenticate", post(did_authenticate))
            . layer(cors_layer)
            .layer(trace_layer)
            .with_state(state);

        let (listener, std_listener, tls_config) = if let Some(tls_config) = tls_config {
            let std_listener = StdTcpListener::bind(format!("{}:{}", config.host, config.port))?;
            std_listener.set_nonblocking(true)?;
            let tls_config = Self::create_tls_config(&tls_config).await?;
            (None, Some(std_listener), Some(tls_config))
        } else {
            let listener =
                tokio::net::TcpListener::bind(format!("{}:{}", config.host, config.port))
                    .await
                    .map_err(|err| eyre!("failed to bind to port {}\n{:?}", config.port, err))?;
            (Some(listener), None, None)
        };

        Ok(Self {
            router,
            listener,
            std_listener,
            tls_config,
        })
    }

    /// Returns the port the server is listening on.
    pub fn port(&self) -> Result<u16> {
        if let Some(std_listener) = &self.std_listener {
            Ok(std_listener.local_addr().map(|addr| addr.port())?)
        } else if let Some(listener) = &self.listener {
            Ok(listener.local_addr().map(|addr| addr.port())?)
        } else {
            Err(eyre!("No listener available to get the port"))
        }
    }

    /// Runs the HTTPS server and returns the bound port and handle.
    pub async fn run_with_port(
        self,
        config: AppServerConfig,
    ) -> Result<(u16, tokio::task::JoinHandle<()>)> {
        let bound_port = self.port()?;
        let handle = if let (Some(std_listener), Some(tls_config)) = (self.std_listener, self.tls_config)
        {
            tracing::debug!("listening on {}", std_listener.local_addr().unwrap());
            let server = axum_server::from_tcp_rustls(std_listener, tls_config)
                .serve(self.router.into_make_service());
            tokio::spawn(async move {
                server.await.expect("Failed to run server");
            })
        } else if let Some(listener) = self.listener {
            tracing::debug!("listening on {}", listener.local_addr().unwrap());
            let server = axum::serve(listener, self.router);
            tokio::spawn(async move {
                server.await.expect("Failed to run server");
            })
        } else {
            return Err(eyre!("No listener available to run the server"));
        };

        Ok((bound_port, handle))
    }

    /// Runs the HTTP/HTTPS server.
    pub async fn run(self) -> Result<()> {
        let (port, handle) = self.run_with_port(AppServerConfig {
            host: "0.0.0.0".to_string(),
            port: 0,
        }).await?;
        tracing::info!("Server running on port {}", port);
        handle.await?;
        Ok(())
    }

    async fn create_tls_config(tls_config: &TlsConfig) -> Result<RustlsConfig> {
        RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
            .await
            .map_err(|err| eyre!("Failed to create TLS config: {}", err))
    }
}