use axum::response::IntoResponse;

pub async fn health_check() -> impl IntoResponse {
    "healthy"
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(
            response.into_response().status(),
            axum::http::StatusCode::OK
        );
    }
}
