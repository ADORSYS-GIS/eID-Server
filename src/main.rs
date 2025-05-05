use axum::{
    Router,
    routing::{get, post},
};
use eid_server::use_id::handlers::use_id_handler;
use eid_server::use_id::service::{EIDService, EIDServiceConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "eid_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting eID-Server");

    // Create EID service with configuration
    let eid_config = EIDServiceConfig {
        max_sessions: 1000,
        session_timeout_minutes: 5,
        ecard_server_address: Some("https://eid.example.com/ecard".to_string()),
    };

    let eid_service = Arc::new(EIDService::new(eid_config));

    // Clone the service for the cleanup task
    let cleanup_service = eid_service.clone();

    // Start background task to periodically clean up expired sessions
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_service.cleanup_expired_sessions().await;
        }
    });

    // Create router with our service endpoint
    let app = Router::new()
        .route("/eIDService/useID", post(use_id_handler))
        .route("/health", get(|| async { "OK" }))
        .layer(TraceLayer::new_for_http())
        .with_state(eid_service);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on {}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app.into_make_service(),
    )
    .await
    .unwrap();
}
