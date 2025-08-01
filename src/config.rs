use config::{Config as ConfigLib, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
        Self::load_with_sources(None)
    }

    pub fn load_with_sources(
        env_vars: Option<HashMap<String, String>>,
    ) -> Result<Self, AppConfigError> {
        let mut builder = ConfigLib::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .add_source(File::with_name("config/settings").required(false));

        if let Some(vars) = env_vars {
            for (key, value) in vars {
                builder = builder.set_override(&key, value)?;
            }
        } else {
            builder = builder.add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            );
        }

        // Build the config once and reuse it
        let built_config = builder.build()?;

        let config = match built_config.try_deserialize::<Config>() {
            Ok(mut config) => {
                if config.redis_url.as_ref().is_some_and(|url| url.is_empty()) {
                    config.redis_url = None;
                }
                config
            }
            Err(_) => {
                let mut base_config = Config {
                    server: ServerConfig::default(),
                    redis_url: None,
                };
                if let Ok(host) = built_config.get_string("server.host") {
                    base_config.server.host = host;
                }
                if let Ok(port) = built_config.get_int("server.port") {
                    base_config.server.port = port as u16;
                }
                base_config
            }
        };

        config.server.transmit.validate().map_err(|e| {
            AppConfigError::Config(ConfigError::Message(format!(
                "TransmitConfig validation failed: {}",
                e
            )))
        })?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_config() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.redis_url, None);
        assert_eq!(config.server.transmit.max_apdu_size, 4096);
        assert_eq!(config.server.tls_cert_path, "Config/cert.pem");
    }

    #[test]
    fn test_env_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert("APP_SERVER__HOST".to_string(), "0.0.0.0".to_string());
        env_vars.insert("APP_SERVER__PORT".to_string(), "443".to_string());
        env_vars.insert(
            "APP_REDIS_URL".to_string(),
            "redis://localhost:6379".to_string(),
        );
        env_vars.insert(
            "APP_SERVER__TRANSMIT__CLIENT_URL".to_string(),
            "http://example.com/eID-Client".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert_eq!(config.redis_url, Some("redis://localhost:6379".to_string()));
        assert_eq!(
            config.server.transmit.client_url,
            "http://example.com/eID-Client"
        );
    }

    #[test]
    fn test_partial_env_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert("APP_SERVER__HOST".to_string(), "192.168.1.1".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");
        assert_eq!(config.server.host, "192.168.1.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.redis_url, None);
    }

    #[test]
    fn test_invalid_transmit_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert(
            "APP_SERVER__TRANSMIT__CLIENT_URL".to_string(),
            "".to_string(),
        );

        let result = Config::load_with_sources(Some(env_vars));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppConfigError::Config(_)));
    }
}
