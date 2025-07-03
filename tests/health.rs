mod common;
use hyper::Client;

#[tokio::test]
async fn test_health_check_works() {
    let addr = common::spawn_server().await;
    let client = Client::new();

    let uri = format!("{}/health", addr)
        .parse()
        .expect("Failed to parse URI");

    let response = client
        .get(uri)
        .await
        .expect("Failed to send request");

    // Verify the response
    assert!(response.status().is_success());
    
    // Check that body is empty
    let body = hyper::body::to_bytes(response.into_body())
        .await
        .expect("Failed to read response body");
    assert!(body.is_empty());
}
