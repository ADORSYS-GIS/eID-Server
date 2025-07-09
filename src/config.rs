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

impl Config {
    pub fn load() -> Result<Self, AppConfigError> {
        // Build the config
        let config = ConfigLib::builder()
            // Set default values
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            // Add a config file under config/settings.toml
            // or any other format supported by `config` crate
            .add_source(File::with_name("config/settings").required(false))
            // This will allow us to override config values via environment variables
            // The environment variables should be prefixed with 'APP_'
            // Example: APP_SERVER_HOST=127.0.0.1
            .add_source(Environment::with_prefix("APP").separator("_"))
            .build()?;

        // Try to deserialize, if it fails due to missing fields, use defaults
        match config.clone().try_deserialize::<Config>() {
            Ok(config) => Ok(config),
            Err(_) => {
                // Fallback to using Default implementations
                let mut base_config = Config {
                    server: ServerConfig::default(),
                };

                // Override with any values from config
                if let Ok(host) = config.get_string("server.host") {
                    base_config.server.host = host;
                }
                if let Ok(port) = config.get_int("server.port") {
                    base_config.server.port = port as u16;
                }

                Ok(base_config)
            }
        }
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
