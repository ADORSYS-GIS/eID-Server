mod utils;

use eid_server::session::MemoryStore;
use eid_server::tls::{TestCertificates, TlsConfig, generate_test_certificates};
use reqwest::{Client, StatusCode};

#[tokio::test]
async fn test_use_id_request_succeeds() {
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();
    let tls_config = TlsConfig::from_pem(server_cert, server_key);
    let addr = utils::spawn_server(MemoryStore::new(), tls_config).await;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let request_xml = include_str!("../test_data/eid/useIDRequest.xml");

    let response = client
        .post(format!("{addr}/eid"))
        .header("Content-Type", "text/xml")
        .body(request_xml)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.text().await.unwrap();
    assert!(body.contains(":Envelope"), "Missing SOAP Envelope: {body}");
    assert!(
        body.contains("<eid:Session>"),
        "Missing Session tag: {body}"
    );
    assert!(body.contains("<eid:PSK>"), "Missing PSK tag: {body}");
    assert!(body.contains("<dss:Result>"), "Missing DSS Result: {body}");
    assert!(body.contains("resultmajor#ok"), "Result is not OK: {body}");
}

#[tokio::test]
async fn test_invalid_body_fails() {
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();
    let tls_config = TlsConfig::from_pem(server_cert, server_key);
    let addr = utils::spawn_server(MemoryStore::new(), tls_config).await;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // wrong element name under Body should trigger schema violation
    let invalid_xml = r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
            <soapenv:Body>
                <eid:unknownRequest />
            </soapenv:Body>
        </soapenv:Envelope>"#;

    let response = client
        .post(format!("{addr}/eid"))
        .header("Content-Type", "text/xml")
        .body(invalid_xml)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("resultmajor#error"),
        "Expected error result: {body}"
    );
    assert!(body.contains("common#unknownAPIFunction"));
}

#[tokio::test]
async fn test_age_verifi_required_but_missing_age_verif_req_fails() {
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();
    let tls_config = TlsConfig::from_pem(server_cert, server_key);
    let addr = utils::spawn_server(MemoryStore::new(), tls_config).await;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // A request where UseOperations marks AgeVerification as REQUIRED
    // but the request does not include AgeVerificationRequest
    let mut xml = include_str!("../test_data/eid/useIDRequest.xml").to_string();
    xml = xml.replace("<eid:AgeVerificationRequest>", "");
    xml = xml.replace("</eid:AgeVerificationRequest>", "");
    xml = xml.replace("<eid:Age>18</eid:Age>", "");

    let response = client
        .post(format!("{addr}/eid"))
        .header("Content-Type", "text/xml")
        .body(xml)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("resultmajor#error"),
        "Expected error result: {body}"
    );
}

#[tokio::test]
async fn test_invalid_psk_fails() {
    // Arrange
    let TestCertificates {
        server_cert,
        server_key,
        ..
    } = generate_test_certificates();
    let tls_config = TlsConfig::from_pem(server_cert, server_key);
    let addr = utils::spawn_server(MemoryStore::new(), tls_config).await;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // invalid PSK: too short id/key
    let base = include_str!("../test_data/eid/useIDRequest.xml");
    let psk_block = "<eid:PSK><eid:ID>short</eid:ID><eid:Key>12345678</eid:Key></eid:PSK>";
    let xml = base.replace(
        "</eid:useIDRequest>",
        &format!("{psk_block}</eid:useIDRequest>"),
    );

    let response = client
        .post(format!("{addr}/eid"))
        .header("Content-Type", "text/xml")
        .body(xml)
        .send()
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("resultmajor#error"),
        "Expected error result: {body}"
    );
}
