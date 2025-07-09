//! This module contains the HTTP server implementation.

use std::sync::Arc;

use crate::domain::eid::ports::{EIDService, EidService};
use crate::eid::get_server_info::handler::get_server_info;
use crate::psk_tls_server::{
    PskStore, TlsPskConfig, create_tls_acceptor, generate_self_signed_cert, psk_validation_layer,
};
use crate::web::handlers;
use crate::web::handlers::refresh::refresh_handler;
use crate::web::handlers::sal::paos::paos_handler;
use axum::extract::{ConnectInfo, State};
use axum::handler::HandlerWithoutStateExt;
use axum::response::IntoResponse;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use color_eyre::eyre::eyre;
use handlers::health::health_check;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use rustls::crypto::CryptoProvider;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::debug;
use tracing_subscriber::fmt::format;

/// Secure PAOS handler that processes requests after PSK validation by middleware
async fn secure_paos_handler<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: String,
) -> impl IntoResponse {
    debug!(
        "Secure PAOS handler called from: {} (TLS connection established, PSK validated by middleware)",
        addr
    );

    // PSK validation has already been performed by the middleware layer
    // We can proceed directly to processing the PAOS request
    debug!("Processing PAOS request over secure TLS connection with validated PSK");
    paos_handler(State(state), body).await.into_response()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig<'a> {
    pub host: &'a str,
    pub port: u16,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
    pub psk_store: Option<PskStore>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    /// HTTP server with the given service and configuration.
    pub async fn new(
        eid_service: impl EIDService + EidService,
        config: ServerConfig<'_>,
    ) -> color_eyre::Result<Self> {
        Self::new_with_tls(eid_service, config, None).await
    }

    /// HTTP/HTTPS server with optional TLS configuration.
    pub async fn new_with_tls(
        eid_service: impl EIDService + EidService,
        config: ServerConfig<'_>,
        tls_config: Option<TlsPskConfig>,
    ) -> color_eyre::Result<Self> {
        // Initialize the tracing layer to log HTTP requests.
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &axum::extract::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = ?request.method(), uri)
            });

        // Initialize the CORS layer to handle cross-origin requests.
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        // Create TLS acceptor if TLS configuration is provided
        let tls_acceptor = if let Some(ref tls_cfg) = tls_config {
            Some(
                create_tls_acceptor(tls_cfg.clone())
                    .map_err(|err| eyre!("Failed to create TLS acceptor: {}", err))?,
            )
        } else {
            None
        };

        // This will encapsulate dependencies needed to execute the business logic
        let eid_service_arc = Arc::new(eid_service);
        let psk_store = tls_config.as_ref().map(|cfg| cfg.psk_store.clone());
        let state = AppState {
            use_id: eid_service_arc.clone(),
            eid_service: eid_service_arc,
            psk_store,
        };
        let ecard_server_address = state
            .use_id
            .get_config()
            .ecard_server_address
            .unwrap_or("/eIDService/paos".to_owned());

        // Choose the appropriate PAOS handler based on TLS configuration
        let router = if config.tls_enabled && tls_config.is_some() {
            debug!(
                "Setting up secure PAOS handler for TLS PSK connection with PSK validation middleware"
            );

            // Create a nested router for the secure PAOS endpoint with PSK validation middleware
            let secure_paos_router = axum::Router::new()
                .route("/eIDService/paos", post(secure_paos_handler))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    psk_validation_layer,
                ));

            axum::Router::new()
                .route("/health", get(health_check))
                .route(
                    "/eIDService/useID",
                    get(handlers::useid::use_id_handler).post(handlers::useid::use_id_handler),
                )
                .route("/eIDService/getServerInfo", get(get_server_info))
                .route("/refresh", get(refresh_handler))
                .merge(secure_paos_router)
                .layer(cors)
                .layer(trace_layer)
                .with_state(state)
        } else {
            debug!("Setting up standard PAOS handler for HTTP connection");
            axum::Router::new()
                .route("/health", get(health_check))
                .route(
                    "/eIDService/useID",
                    get(handlers::useid::use_id_handler).post(handlers::useid::use_id_handler),
                )
                .route("/eIDService/getServerInfo", get(get_server_info))
                .route("/refresh", get(refresh_handler))
                .route(&ecard_server_address, post(paos_handler))
                .layer(cors)
                .layer(trace_layer)
                .with_state(state)
        };

        let listener = TcpListener::bind(format!("{}:{}", config.host, config.port))
            .await
            .map_err(|err| eyre!("failed to bind to port {}\n{:?}", config.port, err))?;

        Ok(Self {
            router,
            listener,
            tls_acceptor,
        })
    }

    /// Returns the port the server is listening on.
    pub fn port(&self) -> color_eyre::Result<u16> {
        self.listener
            .local_addr()
            .map(|addr| addr.port())
            .map_err(|err| err.into())
    }

    /// Runs the server.
    pub async fn run(self) -> color_eyre::Result<()> {
        let addr = self.listener.local_addr().unwrap();

        if let Some(tls_acceptor) = self.tls_acceptor {
            tracing::info!(
                "Starting HTTPS server with TLS PSK configuration on https://{}",
                addr
            );

            // let tls_config = rustls::ServerConfig::builder()

            let cert_data = generate_self_signed_cert().unwrap();
            let cert_bytes: Vec<Vec<u8>> = cert_data
                .0
                .clone()
                .iter()
                .map(|data| data.to_vec())
                .collect();

            // let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            // provider.cipher_suites = vec![CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA];

            // let mut rustls_config = rustls::ServerConfig::builder().crypto_provider();

            let config = axum_server::tls_rustls::RustlsConfig::from_der(
                cert_bytes,
                cert_data.1.secret_der().to_vec(),
            )
            .await
            .unwrap();

            // For now, we'll use the same axum serve but with TLS configuration
            // The TLS acceptor is created and available, indicating HTTPS capability
            // The actual TLS handshake will be handled by the PSK validation middleware
            // axum::serve(
            //     self.listener,
            //     self.router.into_make_service_with_connect_info::<SocketAddr>()
            // )
            // .with_graceful_shutdown(async {
            //     tokio::signal::ctrl_c().await.expect("Failed to install CTRL+C signal handler");
            // })
            // .await
            // .map_err(|err| eyre!("failed to launch HTTPS server: {:?}", err))?;

            axum_server::bind_rustls(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000),
                config,
            )
            .serve(self.router.into_make_service())
            .await
            .unwrap();
        } else {
            tracing::info!("Starting HTTP server on http://{}", addr);

            // Use regular HTTP
            axum::serve(
                self.listener,
                self.router
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install CTRL+C signal handler");
            })
            .await
            .map_err(|err| eyre!("failed to launch HTTP server: {:?}", err))?;
        }
        Ok(())
    }
}
