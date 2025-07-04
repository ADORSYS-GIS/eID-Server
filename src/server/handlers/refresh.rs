use axum::{http::StatusCode, response::Redirect};

// Replace this URL with your actual eService or result page URL
const ESERVICE_URL: &str = "https://localhost:8443/";

pub async fn refresh_handler() -> (StatusCode, Redirect) {
    (StatusCode::SEE_OTHER, Redirect::to(ESERVICE_URL))
}
