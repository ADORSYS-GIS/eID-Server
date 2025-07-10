use axum::{http::StatusCode, response::Redirect};

pub async fn refresh_handler() -> (StatusCode, Redirect) {
    // Read from environment variable or fallback to default URL
    let url = std::env::var("REFRESH_REDIRECT_URL")
        .unwrap_or_else(|_| "https://localhost:8443/".to_string());

    (StatusCode::SEE_OTHER, Redirect::to(&url))
}
