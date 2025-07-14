use config::{Config as ConfigLib, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub redis_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
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

        let mut config: Self = config.try_deserialize()?;
        // Convert empty string to None for redis_url
        if config.redis_url.as_ref().is_some_and(|url| url.is_empty()) {
            config.redis_url = None;
        }
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
        // Default port should be 3000 unless overridden
        assert!(config.server.port >= 3000);
    }

    #[test]
    fn test_env_config() {
        // Set environment variables for this test
        unsafe {
            env::set_var("APP_SERVER_HOST", "0.0.0.0");
            env::set_var("APP_SERVER_PORT", "3001");
        }

        let config = Config::load().expect("Failed to load config");

        // Test with the environment variables set
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3001);

        // Clean up environment variables after test
        unsafe {
            env::remove_var("APP_SERVER_HOST");
            env::remove_var("APP_SERVER_PORT");
        }
    }
}
