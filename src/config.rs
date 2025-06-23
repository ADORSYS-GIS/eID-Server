use config::ConfigError as ExternalConfigError;
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppConfigError {
    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),
    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),
    #[error("Configuration error: {0}")]
    Config(#[from] ExternalConfigError),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub transmit: TransmitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmitConfig {
    pub max_apdu_size: usize,
    pub session_timeout_secs: u64,
    pub max_requests_per_minute: u32,
    pub allowed_cipher_suites: Vec<String>,
    pub require_client_certificate: bool,
    pub min_tls_version: String,
    pub client_url: String,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        // Read URLs from environment variables with fallback to defaults
        let client_url = env::var("EID_CLIENT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:24727/eID-Client".to_string());

        Self {
            max_apdu_size: 4096,
            session_timeout_secs: 300,
            max_requests_per_minute: 60,
            allowed_cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
            ],
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
            client_url,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            transmit: TransmitConfig::default(),
        }
    }
}

impl ServerConfig {
    pub fn from_env() -> Self {
        let host = std::env::var("APP_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        let port = std::env::var("EID_SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080);

        let transmit = TransmitConfig {
            max_apdu_size: std::env::var("APP_TRANSMIT_MAX_APDU_SIZE")
                .unwrap_or_else(|_| "4096".to_string())
                .parse()
                .unwrap_or(4096),
            session_timeout_secs: std::env::var("APP_TRANSMIT_SESSION_TIMEOUT")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .unwrap_or(300),
            max_requests_per_minute: std::env::var("APP_TRANSMIT_MAX_REQUESTS_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            allowed_cipher_suites: std::env::var("APP_TRANSMIT_ALLOWED_CIPHER_SUITES")
                .unwrap_or_else(|_| "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            require_client_certificate: std::env::var("APP_TRANSMIT_REQUIRE_CLIENT_CERTIFICATE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            min_tls_version: std::env::var("APP_TRANSMIT_MIN_TLS_VERSION")
                .unwrap_or_else(|_| "TLSv1.2".to_string()),
            client_url: std::env::var("EID_CLIENT_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:24727/eID-Client".to_string()),
        };

        Self {
            host,
            port,
            transmit,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, AppConfigError> {
        // Load configuration from environment variables
        let client_url = env::var("EID_CLIENT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:24727/eID-Client".to_string());

        let config = Config {
            server: ServerConfig {
                host: env::var("APP_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("EID_SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                transmit: TransmitConfig {
                    client_url,
                    max_apdu_size: 4096,
                    max_requests_per_minute: 60,
                    require_client_certificate: true,
                    min_tls_version: "TLSv1.2".to_string(),
                    session_timeout_secs: 30,
                    allowed_cipher_suites: vec![
                        "TLS_AES_128_GCM_SHA256".to_string(),
                        "TLS_AES_256_GCM_SHA384".to_string(),
                        "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                    ],
                },
            },
        };

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        // This test simply checks that the config loads successfully with some value
        let config = Config::load().expect("Failed to load config");

        // Just verify we can load the config and it has some host value
        assert!(!config.server.host.is_empty());
        // Default port should be 8080 unless overridden
        assert!(config.server.port >= 8080);
    }

    #[test]
    fn test_env_config() {
        // Set environment variables for this test
        unsafe {
            env::set_var("APP_SERVER_HOST", "0.0.0.0");
            env::set_var("APP_SERVER_PORT", "8080");
            env::set_var("EID_CLIENT_URL", "http://127.0.0.1:24727/eID-Client");
        }

        Config::load().expect("Failed to load config");

        // Clean up environment variables after test
        unsafe {
            env::remove_var("APP_SERVER_HOST");
            env::remove_var("APP_SERVER_PORT");
            env::remove_var("EID_CLIENT_URL");
        }
    }
}
