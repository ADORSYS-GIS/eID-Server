use eid_server::{
    domain::eid::{ports::EidService, service::Service},
    server::{Server, ServerConfig},
};
use reqwest::Client;
use std::net::SocketAddr;

/// Test that the getServerInfo endpoint returns a valid XML response
#[tokio::test]
async fn test_server_info_endpoint() {
    // Set up a test server with explicit host and port
    let service = Service::new();
    let config = ServerConfig {
        host: "127.0.0.1",
        port: 0, // Let OS assign a port
    };

    // Start the server
    let server = Server::new(service, config).await.unwrap();
    let port = server.port().unwrap();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], port));

    // Spawn the server in the background
    tokio::spawn(async move {
        server.run().await.unwrap();
    });

    // Allow server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create HTTP client
    let client = Client::new();

    // Test the endpoint
    let response = client
        .get(format!("http://{}/eIDService/getServerInfo", server_addr))
        .header("Accept", "application/xml")
        .send()
        .await
        .unwrap();

    // Verify response status
    assert_eq!(response.status(), 200);

    // Verify content type
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/xml"));

    // Get response body
    let body = response.text().await.unwrap();

    // Print as bytes for debugging
    println!("XML Response: {}", body);
    println!("XML Bytes: {:?}", body.as_bytes());

    // Check for key XML elements based on actual XML structure
    assert!(body.contains("<ServerInfo>"));
    assert!(body.contains("<Version>"));
    // Check for server name - less specific checks
    assert!(body.contains("eID-Server"));
    assert!(body.contains("<SupportedAPIVersions>"));

    // Check for the new TR-03130 required fields
    assert!(body.contains("<ServerVersion>"));
    assert!(body.contains("<DocumentVerificationRights>"));
    assert!(body.contains("<Supported>"));

    // Make sure 1.1 is not included
    assert!(!body.contains("<SupportedAPIVersions>1.1</SupportedAPIVersions>"));
}

/// Test the content of server info returned by the service
#[test]
fn test_server_info_content() {
    // Create service and get server info
    let service = Service::new();
    let server_info = service.get_server_info();

    // Validate content matches expectations
    assert_eq!(server_info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(server_info.name, "eID-Server (SOAP-based Implementation)");
    assert_eq!(server_info.supported_api_versions.len(), 1);
    assert!(
        server_info
            .supported_api_versions
            .contains(&"1.0".to_string())
    );

    // Validate new TR-03130 required fields
    assert_eq!(server_info.server_version, "1.0");
    assert!(!server_info.document_verification_rights.supported);
    assert_eq!(server_info.document_verification_rights.version, None);
}
