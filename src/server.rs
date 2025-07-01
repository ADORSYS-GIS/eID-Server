//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;

use crate::eid::get_server_info::handler::get_server_info;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use color_eyre::eyre::eyre;
use handlers::health::health_check;
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::TlsConfig,
    domain::eid::ports::{EIDService, EidService},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig<'a> {
    pub host: &'a str,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub eid_service: Arc<S>,
}

pub struct Server {
    router: Router,
    listener: Option<TcpListener>,
    std_listener: Option<StdTcpListener>,
    tls_config: Option<RustlsConfig>,
}

impl Server {
    /// Creates a new HTTP server with the given service and configuration.
    pub async fn new(
        eid_service: impl EIDService + EidService,
        config: ServerConfig<'_>,
        tls_config: Option<TlsConfig>,
    ) -> color_eyre::Result<Self> {
        // Initialize the tracing layer to log HTTP requests.
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = ?request.method(), uri)
            });

        // Initialize the CORS layer to handle cross-origin requests.
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods(vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        // This will encapsulate dependencies needed to execute the business logic
        let eid_service_arc = Arc::new(eid_service);
        let state = AppState {
            eid_service: eid_service_arc,
        };

        let router = axum::Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(handlers::useid::use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .layer(cors)
            .layer(trace_layer)
            .with_state(state);

        let (listener, std_listener, tls_config) = if let Some(tls_config) = tls_config {
            let std_listener = StdTcpListener::bind(format!("{}:{}", config.host, config.port))?;
            std_listener.set_nonblocking(true)?;
            let tls_config = create_tls_config(&tls_config).await?;
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
    pub fn port(&self) -> color_eyre::Result<u16> {
        if let Some(std_listener) = &self.std_listener {
            Ok(std_listener.local_addr().map(|addr| addr.port())?)
        } else if let Some(listener) = &self.listener {
            Ok(listener.local_addr().map(|addr| addr.port())?)
        } else {
            Err(eyre!("No listener available to get the port"))
        }
    }

    /// Runs the server.
    pub async fn run(self) -> color_eyre::Result<()> {
        if let (Some(std_listener), Some(tls_config)) = (self.std_listener, self.tls_config) {
            tracing::debug!("listening on {}", std_listener.local_addr().unwrap());
            axum_server::from_tcp_rustls(std_listener, tls_config)
                .serve(self.router.into_make_service())
                .await
                .map_err(|err| eyre!("failed to launch server: {:?}", err))?;
        } else if let Some(listener) = self.listener {
            tracing::debug!("listening on {}", listener.local_addr().unwrap());
            axum::serve(listener, self.router)
                .await
                .map_err(|err| eyre!("failed to launch server: {:?}", err))?;
        } else {
            return Err(eyre!("No listener available to run the server"));
        }
        Ok(())
    }
}

async fn create_tls_config(tls_config: &TlsConfig) -> color_eyre::Result<RustlsConfig> {
    RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .await
        .map_err(|err| eyre!("Failed to create TLS config: {}", err))
}
