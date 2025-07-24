//! This module contains the HTTP server implementation.

mod handlers;
mod responses;
pub mod session;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::eid::get_server_info::handler::get_server_info;
use crate::server::handlers::refresh::refresh_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};
use color_eyre::eyre::{Context, Result};
use handlers::did_auth::did_authenticate;
use handlers::health::health_check;
use handlers::transmit::transmit_handler;
use handlers::useid::use_id_handler;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::config::TransmitConfig;
use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::domain::eid::service::HttpTransmitService;
use crate::domain::eid::transmit::{channel::TransmitChannel, protocol::ProtocolHandler};
use crate::server::session::SessionManager;

#[derive(Debug, Clone)]
pub struct AppServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub transmit: TransmitConfig,
}
use crate::tls::TlsConfig;

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
    pub transmit_channel: Arc<TransmitChannel>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
    tls_config: Arc<TlsConfig>,
}

impl Server {
    /// Creates a new HTTPS server.
    pub async fn new(
        eid_service: impl EIDService + EidService + DIDAuthenticate,
        config: &Config,
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

        // Create Arc for TLS config to share between TransmitChannel and Server
        let tls_config_arc = Arc::new(tls_config);

        // Initialize the TransmitChannel components
        let protocol_handler = ProtocolHandler::new();
        let session_manager = SessionManager::new(Duration::from_secs(
            config.server.transmit.session_timeout_secs,
        ));
        let transmit_service = Arc::new(
            HttpTransmitService::new(config.server.transmit.clone())
                .wrap_err("Failed to create transmit service")?,
        );
        let transmit_channel = Arc::new(
            TransmitChannel::new(
                protocol_handler,
                session_manager,
                transmit_service,
                config.server.transmit.clone(),
                tls_config_arc.clone(),
            )
            .wrap_err("Failed to create transmit channel")?,
        );

        let state = AppState {
            use_id: eid_service_arc.clone(),
            eid_service: eid_service_arc,
            transmit_channel,
        };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(use_id_handler))
            .route("/eIDService/useID", get(use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .route("/eIDService/transmit", post(transmit_handler))
            .route("/did-authenticate", post(did_authenticate))
            .route("/refresh", get(refresh_handler))
            .layer(cors_layer)
            .layer(trace_layer)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .wrap_err_with(|| format!("Failed to bind to port {}", config.server.port))?;

        Ok(Self {
            router,
            listener,
            tls_config: tls_config_arc,
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
    use crate::tls::{TestCertificates, generate_test_certificates};

    #[tokio::test]
    async fn test_server_creation() {
        let mut config = Config::load().expect("Failed to load config");
        config.server.host = "127.0.0.1".to_string();
        config.server.port = 0; // Use port 0 to get a random available port

        let TestCertificates {
            server_cert,
            server_key,
            ..
        } = generate_test_certificates();

        let tls_config = TlsConfig::new(server_cert, server_key);
        let eid_service = UseidService::new(EIDServiceConfig::default());
        let _server = Server::new(eid_service, &config, tls_config)
            .await
            .expect("Failed to create server");
    }

    #[tokio::test]
    async fn test_server_with_custom_transmit_config() {
        let mut config = Config::load().expect("Failed to load config");
        config.server.host = "127.0.0.1".to_string();
        config.server.port = 0;
        config.server.transmit.max_apdu_size = 8192;
        config.server.transmit.session_timeout_secs = 600;
        config.server.transmit.allowed_cipher_suites = vec!["TLS_AES_128_GCM_SHA256".to_string()];

        let TestCertificates {
            server_cert,
            server_key,
            ..
        } = generate_test_certificates();

        let tls_config = TlsConfig::new(server_cert, server_key);
        let eid_service = UseidService::new(EIDServiceConfig::default());
        let _server = Server::new(eid_service, &config, tls_config)
            .await
            .expect("Failed to create server");
    }
}
