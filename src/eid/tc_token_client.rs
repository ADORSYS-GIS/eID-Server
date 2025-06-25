use reqwest::{Client, StatusCode, Url};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Stores the server certificate chain for later authenticity checks
#[derive(Debug, Default, Clone)]
pub struct ServerCertStore {
    pub certs: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl ServerCertStore {
    pub async fn add_cert(&self, cert: Vec<u8>) {
        self.certs.lock().await.insert(cert);
    }
    pub async fn all(&self) -> Vec<Vec<u8>> {
        self.certs.lock().await.iter().cloned().collect()
    }
}

/// Fetches the TC Token from a URL, following redirects and enforcing HTTPS
pub async fn fetch_tc_token_with_certs(tc_token_url: &str, _cert_store: &ServerCertStore) -> Result<String, String> {
    let mut current_url = tc_token_url.to_string();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // handle redirects manually
        .build()
        .map_err(|e| e.to_string())?;
    let mut redirects = 0;
    while redirects < 5 {
        if !current_url.starts_with("https://") {
            return Err(format!("Non-HTTPS URL encountered: {}", current_url));
        }
        let resp = client.get(&current_url).send().await.map_err(|e| e.to_string())?;
        // Store the server certificate if available (native-tls only; reqwest/rustls does not expose this yet)
        // Placeholder: In a real implementation, use a TLS library that exposes peer certificates.
        // cert_store.add_cert(cert_bytes).await;
        if resp.status().is_redirection() {
            if let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                let next_url = Url::parse(location)
                    .or_else(|_| Url::parse(&format!("{}{}", current_url, location)))
                    .map_err(|e| e.to_string())?;
                current_url = next_url.to_string();
                redirects += 1;
                continue;
            } else {
                return Err("Redirect without Location header".to_string());
            }
        }
        if resp.status() == StatusCode::OK {
            let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok());
            if content_type != Some("text/xml; charset=utf-8") && content_type != Some("application/xml; charset=utf-8") {
                return Err(format!("Invalid Content-Type for TC Token: {:?}", content_type));
            }
            let body = resp.text().await.map_err(|e| e.to_string())?;
            return Ok(body);
        } else {
            return Err(format!("Failed to fetch TC Token: {}", resp.status()));
        }
    }
    Err("Too many redirects while fetching TC Token".to_string())
} 