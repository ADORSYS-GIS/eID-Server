mod errors;
mod handlers;
mod responses;

use std::net::TcpListener;
use std::sync::Arc;

use crate::config::Config;
use crate::domain::service::Service;
use crate::pki::truststore::TrustStore;
use crate::server::handlers::health::health_check;
use crate::tls::TlsConfig;
use axum::http::Method;
use axum::routing::post;
use axum::{Router, routing::get};
use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};
use color_eyre::eyre::{Context, Result};
use handlers::process_authentication;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Debug, Clone)]
pub struct AppState<T: TrustStore> {
    pub service: Service<T>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
    tls_config: TlsConfig,
}

impl Server {
    /// Creates a new HTTPS server.
    pub async fn new<T: TrustStore>(
        service: Service<T>,
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

        let state = AppState { service };

        let router = Router::new()
            .route("/health", get(health_check))
            .route("/", post(process_authentication))
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
