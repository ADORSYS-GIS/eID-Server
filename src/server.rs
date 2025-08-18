//! This module contains the HTTP server implementation.

mod handlers;
mod responses;
pub mod session;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use crate::config::TransmitConfig;
use crate::domain::eid::session_manager::SessionManager;
use crate::eid::get_server_info::handler::get_server_info;
use crate::server::handlers::paos::paos_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};
use color_eyre::eyre::{Context, Result, eyre};
use handlers::health::health_check;
use handlers::useid::use_id_handler;
// Note: transmit_handler import removed - transmit functionality integrated within PAOS workflow
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::domain::eid::service::HttpTransmitService;
use crate::domain::eid::transmit::{channel::TransmitChannel, protocol::ProtocolHandler};
use crate::server::session::SessionManager as ServerSessionManager;
use crate::tls::TlsConfig;

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
    listener: TcpListener,
    tls_config: TlsConfig,
}

impl Server {
    /// Creates a new HTTPS server.
    pub async fn new(
        eid_service: impl EIDService + EidService + DIDAuthenticate + SessionManager + 'static,
        config: AppServerConfig,
        tls_config: TlsConfig,
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
            ServerSessionManager::new(Duration::from_secs(config.transmit.session_timeout_secs));
        let transmit_service = Arc::new(
            HttpTransmitService::new(config.transmit.clone())
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
            .route("/", post(paos_handler))
            .nest(
                "/eIDService",
                Router::new()
                    .route("/useID", post(use_id_handler))
                    .route("/useID", get(use_id_handler))
                    .route("/getServerInfo", get(get_server_info)),
                    // Note: Transmit endpoint removed - transmit functionality is now integrated within PAOS workflow
            )
            .layer(cors_layer)
            .layer(trace_layer)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.host, config.port))
            .wrap_err_with(|| format!("Failed to bind to port {}", config.port))?;

        Ok(Self {
            router,
            listener,
            tls_config,
        })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    /// Runs the HTTPS server.
    pub async fn run(self) -> Result<()> {
        let tls_acceptor = self.tls_config.build_acceptor()?;
        let config = OpenSSLConfig::from_acceptor(Arc::new(tls_acceptor));
        let acceptor = OpenSSLAcceptor::new(config);

        tracing::info!(
            "Server listening on https://{}",
            self.listener.local_addr()?
        );
        axum_server::from_tcp(self.listener)
            .acceptor(acceptor)
            .serve(self.router.into_make_service())
            .await?;
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
                max_retries: 3,
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
        let tls_config = TlsConfig::new(config.tls_cert_path.clone(), config.tls_key_path.clone()); // Pass cert and key paths
        let _server = Server::new(eid_service, config, tls_config)
            .await
            .expect("Failed to create server");
    }

    #[tokio::test]
    async fn test_server_with_custom_transmit_config() {
        let transmit_config = TransmitConfig {
            max_apdu_size: 8192,
            session_timeout_secs: 600,
            max_retries: 3,
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
        let tls_config = TlsConfig::new(config.tls_cert_path.clone(), config.tls_key_path.clone()); // Pass cert and key paths
        let _server = Server::new(eid_service, config, tls_config)
            .await
            .expect("Failed to create server");
    }
}
