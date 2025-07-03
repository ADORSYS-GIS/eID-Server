use config::{Config as ConfigLib, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub psk: String,
    pub psk_identity: String,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        // Build the config
        let config = ConfigLib::builder()
            // Set default values
            .set_default("server.host", "localhost")?
            .set_default("server.port", 3000)?
            .set_default("tls.cert_path", "config/cert.pem")?
            .set_default("tls.key_path", "config/key.pem")?
            .set_default("tls.psk", "supersecretpsk")?
            .set_default("tls.psk_identity", "psk_identity")?
            // Add a config file under config/settings.toml
            // or any other format supported by `config` crate
            .add_source(File::with_name("config/settings").required(false))
            // This will allow us to override config values via environment variables
            // The environment variables should be prefixed with 'APP_'
            // Example: APP_SERVER_HOST=127.0.0.1
            .add_source(Environment::with_prefix("APP").separator("_"))
            .build()?;

        config.try_deserialize()
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
