mod utils;

use std::sync::Arc;

use eid_server::session::MemoryStore;
use eid_server::tls::{TlsConfig, generate_ca_certificate, generate_leaf_certificate};
use reqwest::{Certificate, Client, Identity};

#[tokio::test]
async fn test_mutual_tls_works() {
    // ======= building the server =======

    let (ca_cert, ca_key) = generate_ca_certificate();
    let (server_cert, server_key) = generate_leaf_certificate(&ca_cert, &ca_key);

    let session_store = MemoryStore::new();
    let tls_config = TlsConfig::from_pem(server_cert, server_key)
        .with_client_auth(&[ca_cert.to_pem().unwrap()])
        .with_session_store(Arc::new(session_store.clone()));

    let addr = utils::spawn_server(session_store, tls_config).await;

    // ======= building the client =======

    let (client_cert, client_key) = generate_leaf_certificate(&ca_cert, &ca_key);
    let mut combined_pem = Vec::new();
    combined_pem.extend_from_slice(&client_cert);
    combined_pem.extend_from_slice(b"\n");
    combined_pem.extend_from_slice(&client_key);

    let client_cert = Identity::from_pem(&combined_pem).unwrap();
    let ca_cert = Certificate::from_pem(&ca_cert.to_pem().unwrap()).unwrap();

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .identity(client_cert)
        .https_only(true)
        .build()
        .unwrap();

    let response = client.get(format!("{addr}/health")).send().await.unwrap();

    // Verify the response
    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    assert!(body.contains("healthy"));
}
