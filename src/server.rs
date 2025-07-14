//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::eid::get_server_info::handler::get_server_info;
use crate::server::handlers::refresh::refresh_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use color_eyre::eyre::{Result, eyre};
use handlers::did_auth::did_authenticate;
use handlers::health::health_check;
use handlers::transmit::transmit_handler;
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::config::TransmitConfig;
use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::domain::eid::service::{HttpTransmitService, TransmitServiceConfig};
use crate::domain::eid::transmit::{
    channel::TransmitChannel, protocol::ProtocolHandler, session::SessionManager,
};

#[derive(Debug, Clone)]
pub struct AppServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub transmit: TransmitConfig,
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
    pub transmit_channel: Arc<TransmitChannel>,
}

pub struct Server {
    router: Router,
}

impl Server {
    /// Loads TLS certificates using provided paths
    fn load_tls_config(cert_path: &str, key_path: &str) -> Result<RustlsConfig> {
        // Install the default CryptoProvider (ring)
        default_provider()
            .install_default()
            .map_err(|_| eyre!("Failed to install CryptoProvider"))?;

        let cert_file = File::open(Path::new(cert_path))
            .map_err(|e| eyre!("Failed to open cert file at '{}': {}", cert_path, e))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| eyre!("Error reading certs from '{}': {e}", cert_path))?
            .into_iter()
            .collect();

        let key_file = File::open(Path::new(key_path))
            .map_err(|e| eyre!("Failed to open key file at '{}': {}", key_path, e))?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| eyre!("Error reading private key from '{}': {}", key_path, e))?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();

        if keys.is_empty() {
            return Err(eyre!("No private key found in '{}'", key_path));
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
        config: AppServerConfig,
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

        // This will encapsulate dependencies needed to execute the business logic
        let eid_service_arc = Arc::new(eid_service);

        // Initialize the TransmitChannel components
        let protocol_handler = ProtocolHandler::new();
        let session_manager =
            SessionManager::new(Duration::from_secs(config.transmit.session_timeout_secs));
        let transmit_service_config = TransmitServiceConfig::from(config.transmit.clone());
        let transmit_service = Arc::new(
            HttpTransmitService::new(transmit_service_config)
                .map_err(|e| eyre!("Failed to create transmit service: {}", e))?,
        );
        let transmit_channel = Arc::new(
            TransmitChannel::new(
                protocol_handler,
                session_manager,
                transmit_service,
                config.transmit.clone(),
            )
            .map_err(|e| eyre!("Failed to create transmit channel: {}", e))?,
        );

        let state = AppState {
            use_id: eid_service_arc.clone(),
            eid_service: eid_service_arc,
            transmit_channel,
        };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(handlers::useid::use_id_handler))
            .route("/eIDService/useID", get(handlers::useid::use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .route("/eIDService/transmit", post(transmit_handler))
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

        let tls_config = Self::load_tls_config(&config.tls_cert_path, &config.tls_key_path)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::service::{EIDServiceConfig, UseidService};

    #[tokio::test]
    async fn test_server_creation() {
        let config = AppServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Use port 0 to get a random available port
            tls_cert_path: "test_cert.pem".to_string(),
            tls_key_path: "test_key.pem".to_string(),
            transmit: TransmitConfig {
                client_url: "http://127.0.0.1:24727/eID-Client".to_string(),
                max_apdu_size: 4096,
                session_timeout_secs: 30,
                allowed_cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256".to_string(),
                    "TLS_AES_256_GCM_SHA384".to_string(),
                    "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                ],
                max_requests_per_minute: 60,
                require_client_certificate: true,
                min_tls_version: "TLSv1.2".to_string(),
            },
        };

        let eid_service = UseidService::new(EIDServiceConfig::default());
        let _server = Server::new(eid_service, config)
            .await
            .expect("Failed to create server");
    }

    #[tokio::test]
    async fn test_server_with_custom_transmit_config() {
        let transmit_config = TransmitConfig {
            max_apdu_size: 8192,
            session_timeout_secs: 600,
            allowed_cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
            client_url: "http://localhost:24727/eID-Client".to_string(),
            max_requests_per_minute: 60,
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
        };

        let config = AppServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            tls_cert_path: "test_cert.pem".to_string(),
            tls_key_path: "test_key.pem".to_string(),
            transmit: transmit_config,
        };

        let eid_service = UseidService::new(EIDServiceConfig::default());
        let _server = Server::new(eid_service, config)
            .await
            .expect("Failed to create server");
    }
}
