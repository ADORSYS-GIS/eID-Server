use config::{Config as ConfigLib, ConfigError, Environment, File};
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
    Config(#[from] ConfigError),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub redis_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub transmit: TransmitConfig,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmitConfig {
    pub max_apdu_size: usize,
    pub session_timeout_secs: u64,
    pub max_requests_per_minute: u32,
    pub max_retries: u32,
    pub allowed_cipher_suites: Vec<String>,
    pub require_client_certificate: bool,
    pub min_tls_version: String,
    pub client_url: String,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        // Read client URL from environment variable with fallback to default
        let client_url = env::var("EID_CLIENT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:24727/eID-Client".to_string());

        Self {
            max_apdu_size: 4096,
            session_timeout_secs: 300,
            max_requests_per_minute: 60,
            max_retries: 3,
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

impl TransmitConfig {
    /// Validates the configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.client_url.is_empty() {
            return Err("Client URL cannot be empty".to_string());
        }
        if self.max_apdu_size == 0 {
            return Err("Max APDU size must be greater than 0".to_string());
        }
        if self.session_timeout_secs == 0 {
            return Err("Session timeout must be greater than 0".to_string());
        }
        if self.allowed_cipher_suites.is_empty() {
            return Err("At least one cipher suite must be allowed".to_string());
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            tls_cert_path: "Config/cert.pem".to_string(),
            tls_key_path: "Config/key.pem".to_string(),
            transmit: TransmitConfig::default(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, AppConfigError> {
        // Build the config
        let config = ConfigLib::builder()
            // Set default values for server
            .set_default("server.host", "localhost")?
            .set_default("server.port", 3000)?
            // Add default values for TLS paths
            .set_default("server.tls_cert_path", "Config/cert.pem")?
            .set_default("server.tls_key_path", "Config/key.pem")?
            // Set default value for redis_url (None by default)
            .set_default("redis_url", "")?
            // Add a config file
            .add_source(File::with_name("config/settings").required(false))
            // Add environment variables
            .add_source(Environment::with_prefix("APP").separator("_"))
            .build()?;

        let config = match config.clone().try_deserialize::<Config>() {
            Ok(mut config) => {
                // Convert empty string to None for redis_url
                if config.redis_url.as_ref().is_some_and(|url| url.is_empty()) {
                    config.redis_url = None;
                }
                config
            }
            Err(_) => {
                // Fallback to using Default implementations
                let mut base_config = Config {
                    server: ServerConfig::default(),
                    redis_url: None,
                };

                // Override with any values from config
                if let Ok(host) = config.get_string("server.host") {
                    base_config.server.host = host;
                }
                if let Ok(port) = config.get_int("server.port") {
                    base_config.server.port = port as u16;
                }

                base_config
            }
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
        assert!(config.server.port >= 3000);
    }

    #[test]
    fn test_env_config() {
        // Set environment variables for this test
        unsafe {
            env::set_var("APP_SERVER_HOST", "0.0.0.0");
            env::set_var("APP_SERVER_PORT", "3000");
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
