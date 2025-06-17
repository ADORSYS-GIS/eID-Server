//! This module contains the HTTP server implementation.

mod handlers;
mod responses;

use std::sync::Arc;

use crate::eid::get_server_info::handler::get_server_info;
use axum::{Router, routing::get};
use axum::{http::Method, routing::post};
use color_eyre::eyre::eyre;
use handlers::health::health_check;
use handlers::did_auth::did_authenticate;
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::domain::eid::ports::{DIDAuthenticate, EIDService, EidService};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig<'a> {
    pub host: &'a str,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AppState<S: EIDService + EidService> {
    pub use_id: Arc<S>,
    pub eid_service: Arc<S>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    /// Creates a new HTTP server with the given service and configuration.
    pub async fn new(
        eid_service: impl EIDService + EidService + DIDAuthenticate,
        config: ServerConfig<'_>,
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

        // This will encapsulate dependencies needed to execute the business logic
        let eid_service_arc = Arc::new(eid_service);
        let state = AppState {
            use_id: eid_service_arc.clone(),
            eid_service: eid_service_arc,
        };

        let router = axum::Router::new()
            .route("/health", get(health_check))
            .route("/eIDService/useID", post(handlers::useid::use_id_handler))
            .route("/eIDService/useID", get(handlers::useid::use_id_handler))
            .route("/eIDService/getServerInfo", get(get_server_info))
            .route("/did-authenticate", post(did_authenticate)) 
            .layer(cors)
            .layer(trace_layer)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.host, config.port))
            .await
            .map_err(|err| eyre!("failed to bind to port {}\n{:?}", config.port, err))?;
        Ok(Self { router, listener })
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
        tracing::debug!("listening on {}", self.listener.local_addr().unwrap());
        axum::serve(self.listener, self.router)
            .await
            .map_err(|err| eyre!("failed to launch server: {:?}", err))?;
        Ok(())
    }
}
