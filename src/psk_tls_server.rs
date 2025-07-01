use crate::config::Config;
use crate::domain::eid::service::UseidService;
use axum::{Router, body::Body};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use lazy_static::lazy_static;
use libc;
use openssl::ssl::{Ssl, SslContext, SslContextBuilder};
use openssl::ssl::{SslFiletype, SslMethod};
use openssl_sys;
use rcgen;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;
use tower::ServiceExt;

// Store PSK identities and keys
lazy_static! {
    static ref PSK_STORE: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
}

// Add a PSK to the store
pub fn add_psk(identity: String, key: String) {
    let identity_clone = identity.clone();
    let mut store = PSK_STORE.write().unwrap();
    store.insert(identity, key);
    println!("Added PSK for identity: {}", identity_clone);
}

// PSK callback function for OpenSSL
extern "C" fn psk_server_callback(
    _ssl: *mut openssl_sys::SSL,
    identity: *const libc::c_char,
    psk: *mut libc::c_uchar,
    max_psk_len: libc::c_uint,
) -> libc::c_uint {
    use std::ffi::CStr;
    use std::slice;

    unsafe {
        // Convert identity to Rust string
        let identity_str = match CStr::from_ptr(identity).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return 0, // Error in identity
        };

        println!("PSK callback received identity: {}", identity_str);

        // Look up the PSK for this identity
        let store = PSK_STORE.read().unwrap();
        let psk_key = match store.get(&identity_str) {
            Some(key) => key,
            None => {
                println!("PSK not found for identity: {}", identity_str);
                return 0; // Identity not found
            }
        };

        // Copy PSK to output buffer
        let psk_bytes = psk_key.as_bytes();
        let psk_len = std::cmp::min(psk_bytes.len(), max_psk_len as usize);

        let psk_slice = slice::from_raw_parts_mut(psk, psk_len);
        psk_slice.copy_from_slice(&psk_bytes[..psk_len]);

        println!("PSK found and set for identity: {}", identity_str);
        psk_len as libc::c_uint
    }
}

// Register a session PSK
pub fn register_session_psk(session_id: String, psk: String) {
    add_psk(session_id, psk);
}

pub async fn run_psk_tls_server(
    config: &Config,
    eid_service: UseidService,
) -> color_eyre::Result<()> {
    // Add the default PSK from config to the PSK store
    add_psk(config.tls.psk_identity.clone(), config.tls.psk.clone());

    // Register existing sessions from the eid_service
    let sessions = eid_service.sessions.read().unwrap();
    for session in sessions.iter() {
        if let Some(psk) = &session.psk {
            register_session_psk(session.id.clone(), psk.clone());
        }
    }
    drop(sessions);

    // Create a shared SSL context for all connections
    let ssl_ctx = Arc::new(create_psk_ssl_context(config)?);

    let router: Router<()> = Router::new().route("/health", axum::routing::get(|| async { "OK" }));
    let router = Arc::new(router);
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await?;
    println!("PSK TLS server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let ssl_ctx = ssl_ctx.clone();
        let router = router.clone();
        let _eid_service = eid_service.clone();

        tokio::spawn(async move {
            // Create a new SSL instance for each connection
            let ssl = Ssl::new(&ssl_ctx).unwrap();
            let mut ssl_stream = match SslStream::new(ssl, stream) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to create SslStream: {}", e);
                    return;
                }
            };

            if let Err(e) = Pin::new(&mut ssl_stream).accept().await {
                eprintln!("TLS handshake failed: {}", e);
                return;
            }

            println!("TLS handshake successful!");

            // Handle the connection with HTTP
            let service = service_fn(move |req: hyper::Request<hyper::Body>| {
                let router = router.clone();
                async move {
                    // Convert hyper request to axum request
                    let (parts, body) = req.into_parts();

                    // Convert body bytes
                    let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();

                    // Build a new axum request with the same data
                    let axum_req = axum::http::Request::builder()
                        .method(parts.method.as_str())
                        .uri(parts.uri.to_string())
                        .version(match parts.version {
                            hyper::Version::HTTP_09 => axum::http::Version::HTTP_09,
                            hyper::Version::HTTP_10 => axum::http::Version::HTTP_10,
                            hyper::Version::HTTP_11 => axum::http::Version::HTTP_11,
                            hyper::Version::HTTP_2 => axum::http::Version::HTTP_2,
                            hyper::Version::HTTP_3 => axum::http::Version::HTTP_3,
                            _ => axum::http::Version::HTTP_11,
                        });

                    // Copy headers
                    let mut axum_req = axum_req.body(Body::from(body_bytes)).unwrap();
                    for (name, value) in parts.headers.iter() {
                        axum_req.headers_mut().insert(
                            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
                            axum::http::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
                        );
                    }

                    // Process with router
                    match router.as_ref().clone().oneshot(axum_req).await {
                        Ok(res) => {
                            let (parts, body) = res.into_parts();

                            // Build a new hyper response
                            let mut hyper_res = hyper::Response::builder()
                                .status(parts.status.as_u16())
                                .version(match parts.version {
                                    axum::http::Version::HTTP_09 => hyper::Version::HTTP_09,
                                    axum::http::Version::HTTP_10 => hyper::Version::HTTP_10,
                                    axum::http::Version::HTTP_11 => hyper::Version::HTTP_11,
                                    axum::http::Version::HTTP_2 => hyper::Version::HTTP_2,
                                    axum::http::Version::HTTP_3 => hyper::Version::HTTP_3,
                                    _ => hyper::Version::HTTP_11,
                                })
                                .body(hyper::Body::empty())
                                .unwrap();

                            // Copy headers
                            for (name, value) in parts.headers.iter() {
                                hyper_res.headers_mut().insert(
                                    hyper::header::HeaderName::from_bytes(name.as_str().as_bytes())
                                        .unwrap(),
                                    hyper::header::HeaderValue::from_bytes(value.as_bytes())
                                        .unwrap(),
                                );
                            }

                            // Convert body
                            let bytes = axum::body::to_bytes(body, usize::MAX)
                                .await
                                .unwrap_or_default();

                            *hyper_res.body_mut() = hyper::Body::from(bytes);
                            Ok::<_, hyper::Error>(hyper_res)
                        }
                        Err(err) => {
                            let mut res = hyper::Response::new(hyper::Body::from(format!(
                                "Internal server error: {}",
                                err
                            )));
                            *res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                            Ok(res)
                        }
                    }
                }
            });

            if let Err(err) = Http::new().serve_connection(ssl_stream, service).await {
                eprintln!("HTTP error: {}", err);
            }
        });
    }
}

/// Helper function to create an SSL context with PSK support
pub fn create_psk_ssl_context(config: &Config) -> color_eyre::Result<SslContext> {
    // SSL setup with PSK support
    let mut ctx_builder = SslContextBuilder::new(SslMethod::tls_server())?;

    // Set up certificate (still needed for RSA_PSK)
    if std::path::Path::new(&config.tls.cert_path).exists()
        && std::path::Path::new(&config.tls.key_path).exists()
    {
        // Use specified certificate and key files if they exist
        println!(
            "Using certificate at {} and key at {}",
            config.tls.cert_path, config.tls.key_path
        );
        ctx_builder.set_certificate_file(&config.tls.cert_path, SslFiletype::PEM)?;
        ctx_builder.set_private_key_file(&config.tls.key_path, SslFiletype::PEM)?;
    } else {
        // Create a self-signed certificate for development
        println!("Certificate files not found. Creating a temporary self-signed certificate.");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        // Convert PEM strings to DER format
        let cert_der = openssl::x509::X509::from_pem(cert_pem.as_bytes())?;
        let key_der = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes())?;

        ctx_builder.set_certificate(&cert_der)?;
        ctx_builder.set_private_key(&key_der)?;
    }

    // Set PSK callback
    unsafe {
        openssl_sys::SSL_CTX_set_psk_server_callback(
            ctx_builder.as_ptr(),
            Some(psk_server_callback),
        );
    }

    // Set cipher suite to TLS_RSA_PSK_WITH_AES_256_CBC_SHA
    ctx_builder.set_cipher_list("RSA-PSK-AES256-CBC-SHA")?;

    // Build and return the SSL context
    Ok(ctx_builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // Helper function to clear the PSK store between tests
    fn clear_psk_store() {
        let mut store = PSK_STORE.write().unwrap();
        store.clear();
    }

    #[test]
    fn test_add_psk() {
        clear_psk_store();

        // Add a PSK
        let identity = "test_identity".to_string();
        let key = "test_key".to_string();
        add_psk(identity.clone(), key.clone());

        // Verify it was added correctly
        let store = PSK_STORE.read().unwrap();
        assert!(store.contains_key(&identity));
        assert_eq!(store.get(&identity).unwrap(), &key);
    }

    #[test]
    fn test_register_session_psk() {
        clear_psk_store();

        // Register a session PSK
        let session_id = "test_session".to_string();
        let psk = "test_session_key".to_string();
        register_session_psk(session_id.clone(), psk.clone());

        // Verify it was registered correctly
        let store = PSK_STORE.read().unwrap();
        assert!(store.contains_key(&session_id));
        assert_eq!(store.get(&session_id).unwrap(), &psk);
    }

    #[test]
    fn test_create_psk_ssl_context_with_existing_cert() -> color_eyre::Result<()> {
        // Create a temporary directory for test certificates
        let temp_dir = tempdir()?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Generate a self-signed certificate for testing
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        // Write the certificate and key to files
        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

        // Create a config with the test certificate paths
        let config = Config {
            server: crate::config::ServerConfig {
                host: "localhost".to_string(),
                port: 8443,
            },
            tls: crate::config::TlsConfig {
                cert_path: cert_path.to_str().unwrap().to_string(),
                key_path: key_path.to_str().unwrap().to_string(),
                psk: "test_psk".to_string(),
                psk_identity: "test_identity".to_string(),
            },
        };

        // Test creating the SSL context
        let _ssl_ctx = create_psk_ssl_context(&config)?;

        // If we get here without errors, the test passes
        assert!(true);

        Ok(())
    }

    #[test]
    fn test_create_psk_ssl_context_with_self_signed_cert() -> color_eyre::Result<()> {
        // Create a config with non-existent certificate paths
        let config = Config {
            server: crate::config::ServerConfig {
                host: "localhost".to_string(),
                port: 8443,
            },
            tls: crate::config::TlsConfig {
                cert_path: "/non/existent/cert.pem".to_string(),
                key_path: "/non/existent/key.pem".to_string(),
                psk: "test_psk".to_string(),
                psk_identity: "test_identity".to_string(),
            },
        };

        // Test creating the SSL context with self-signed certificate
        let _ssl_ctx = create_psk_ssl_context(&config)?;

        // If we get here without errors, the test passes
        assert!(true);

        Ok(())
    }

    // This test is more complex and would require mocking the OpenSSL callback
    // For now, we'll just test that the PSK callback is set correctly
    #[test]
    fn test_psk_callback_is_set() -> color_eyre::Result<()> {
        clear_psk_store();

        // Add a test PSK
        add_psk("test_identity".to_string(), "test_key".to_string());

        // Create a config
        let config = Config {
            server: crate::config::ServerConfig {
                host: "localhost".to_string(),
                port: 8443,
            },
            tls: crate::config::TlsConfig {
                cert_path: "/non/existent/cert.pem".to_string(),
                key_path: "/non/existent/key.pem".to_string(),
                psk: "test_psk".to_string(),
                psk_identity: "test_identity".to_string(),
            },
        };

        // Create the SSL context
        let _ssl_ctx = create_psk_ssl_context(&config)?;

        // We can't directly test the callback, but we can verify the context was created
        assert!(true);

        Ok(())
    }
}
