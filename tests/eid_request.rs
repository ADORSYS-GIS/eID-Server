use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use libflate::deflate::Encoder;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use reqwest::Client;
use std::fs;
use std::io::Write;
use url::form_urlencoded;

#[tokio::test]
async fn test_send_signed_saml_request() {
    // Step 1: Read the signed SAML request
    let signed_xml = fs::read_to_string("./tmp/signed.xml").expect("Signed XML not found");
    println!("Read signed XML successfully");

    // Step 2: Deflate (zlib, raw, no header)
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .write_all(signed_xml.as_bytes())
        .expect("Deflate failed");
    let compressed = encoder
        .finish()
        .into_result()
        .expect("Deflate finish failed");
    println!("Deflated XML successfully");

    // Step 3: Base64 encode
    let b64 = BASE64.encode(&compressed);
    println!("Base64 encoded successfully");

    // Step 4: URL encode
    let saml_request = form_urlencoded::byte_serialize(b64.as_bytes()).collect::<String>();
    println!("SAMLRequest: {saml_request}");

    // Step 5: Prepare SigAlg and RelayState
    let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string();

    // Create a proper RelayState with current timestamp
    let timestamp = Utc::now().timestamp();
    let relay_state = format!(
        "t_C5eLjqYDiBmqsL_jzsdaoqf5z8DBEIieoaRVH6aAk.y9HSXm5nrPs.xVIpjU21QTWs6N-HTtTldw.eyJydSI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMvYWRtaW4vbWFzdGVyL2NvbnNvbGUvIiwicnQiOiJjb2RlIiwicm0iOiJxdWVyeSIsInN0IjoiMWY4NDdhMjctZTMyNC00OTMwLTg4NTMtYTQyMzdjYWNkYmE3In0.{timestamp}"
    );

    // Step 6: Prepare string to sign (as per SAML HTTP POST binding)
    let string_to_sign = format!(
        "SAMLRequest={}&RelayState={}&SigAlg={}",
        saml_request,
        form_urlencoded::byte_serialize(relay_state.as_bytes()).collect::<String>(),
        form_urlencoded::byte_serialize(sig_alg.as_bytes()).collect::<String>()
    );
    println!("String to sign: {string_to_sign}");

    // Step 7: Sign the string_to_sign with the private key from config
    let private_key = fs::read_to_string("./tests/keys/saml_request_private_key.pem")
        .expect("Failed to read private key");
    println!("Read private key successfully");

    let pkey =
        PKey::private_key_from_pem(private_key.as_bytes()).expect("Failed to parse private key");
    println!("Parsed private key successfully");

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("Failed to create signer");
    signer
        .update(string_to_sign.as_bytes())
        .expect("Failed to update signer");
    let signature = signer.sign_to_vec().expect("Failed to sign");
    let signature_b64 = BASE64.encode(signature);
    println!("Generated signature successfully");

    // Step 8: Send it to the test eID server
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create HTTP client");

    println!("Sending request to eID server...");
    let response = client
        .post("https://dev.id.governikus-eid.de/gov_autent/async")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        )
        .header("User-Agent", "Mozilla/5.0")
        .form(&[
            ("SAMLRequest", &saml_request),
            ("RelayState", &relay_state),
            ("SigAlg", &sig_alg),
            ("Signature", &signature_b64),
        ])
        .send()
        .await
        .expect("Failed to send request");

    // Step 9: Check the response
    let status = response.status();
    let body = response.text().await.expect("No body received");

    println!("Response Status: {status}");
    println!("Response Body: {body}");

    if !status.is_success() {
        panic!("Request failed with status: {status}");
    }
}
