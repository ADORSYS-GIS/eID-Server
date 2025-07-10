mod common;

use reqwest::Client;

#[tokio::test]
async fn test_health_check_works() {
    let addr = common::spawn_server().await;

    // Create a custom client that ignores invalid certificates
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client.get(format!("{addr}/health")).send().await.unwrap();

    // Verify the response
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
