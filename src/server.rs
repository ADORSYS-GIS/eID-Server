//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::net::TcpListener;
use std::sync::Arc;

use crate::config::Config;
use crate::eid::get_server_info::handler::get_server_info;
use crate::server::handlers::sal::paos::paos_handler;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};
use color_eyre::eyre::{Context, Result};
use handlers::did_auth::did_authenticate;
use handlers::get_result::get_result_handler;
use handlers::health::health_check;
use handlers::useid::use_id_handler;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};
use crate::tls::TlsConfig;

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
    tls_config: TlsConfig,
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

        let eid_service = Arc::new(eid_service);
        let state = AppState {
            use_id: eid_service.clone(),
            eid_service,
        };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/", post(paos_handler))
            .nest(
                "/eIDService",
                Router::new()
                    .route("/useID", post(use_id_handler))
                    .route("/useID", get(use_id_handler))
                    .route("/getServerInfo", get(get_server_info))
                    .route("/getResult", post(get_result_handler))
            )
            .route("/did-authenticate", post(did_authenticate))
            .layer(cors_layer)
            .layer(trace_layer)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .wrap_err_with(|| format!("Failed to bind to port {}", config.server.port))?;

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
