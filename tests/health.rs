mod utils;

use eid_server::{
    session::MemoryStore,
    tls::{TestCertificates, TlsConfig, generate_test_certificates},
};
use reqwest::Client;

#[tokio::test]
async fn test_health_check_works() {
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();

    // build the tls configuration
    let tls_config = TlsConfig::from_pem(server_cert, server_key);
    let addr = utils::spawn_server(MemoryStore::new(), tls_config).await;

    // Create a custom client that ignores invalid certificates
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client.get(format!("{addr}/health")).send().await.unwrap();

    // Verify the response
    assert!(response.status().is_success());
}
