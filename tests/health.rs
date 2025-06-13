mod common;

use reqwest::Client;

#[tokio::test]
async fn test_health_check_works() {
    let addr = common::spawn_server().await;

    let client = Client::new();
    let response = client.get(format!("{addr}/health")).send().await.unwrap();

    // Verify the response
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
