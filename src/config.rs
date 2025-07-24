use std::collections::HashMap;

use color_eyre::eyre::Result;
use config::{Config as ConfigLib, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub transmit: TransmitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_with_sources(None)
    }

    pub fn load_with_sources(
        env_vars: Option<HashMap<String, String>>,
    ) -> Result<Self, ConfigError> {
        let mut builder = ConfigLib::builder()
            .set_default("server.host", "localhost")?
            .set_default("server.port", 3000)?
            .add_source(File::with_name("config/settings").required(false));

        // If env_vars is provided, we use it instead of system environment
        // This is to avoid systems variables pollution across tests
        if let Some(vars) = env_vars {
            for (key, value) in vars {
                builder = builder.set_override(&key, value)?;
            }
        } else {
            // Use system environment variables
            // Should be in the format APP_SERVER__HOST or APP_SERVER__REDIS_URL
            builder = builder.add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            );
        }

        builder.build()?.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_config() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.redis_url, None);
    }

    #[test]
    fn test_env_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert("server.host".to_string(), "0.0.0.0".to_string());
        env_vars.insert("server.port".to_string(), "443".to_string());
        env_vars.insert(
            "redis_url".to_string(),
            "redis://localhost:6379".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert_eq!(config.redis_url, Some("redis://localhost:6379".to_string()));
    }

    #[test]
    fn test_partial_env_override() {
        let mut env_vars = HashMap::new();
        // We just override the host
        env_vars.insert("server.host".to_string(), "192.168.1.1".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "192.168.1.1");
        // The other values should use default
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.redis_url, None);
    }
}
