use std::{collections::HashMap, time::Duration};

use config::{Config as ConfigLib, ConfigError, Environment, File};
use redis::{
    Client as RedisClient, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub redis: Option<RedisConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
}

impl RedisConfig {
    /// Establishes a new Redis connection based on the provided URI.
    ///
    /// - To enable TLS, the URI must use the `rediss://` scheme.
    /// - To enable insecure TLS, the URI must use the `rediss://` scheme and end with `/#insecure`.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established.
    pub async fn start(&self) -> RedisResult<ConnectionManager> {
        let client = RedisClient::open(self.uri.expose_secret())?;
        let config = ConnectionManagerConfig::new().set_connection_timeout(Duration::from_secs(60));
        client.get_connection_manager_with_config(config).await
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
        assert!(config.redis.is_none());
    }

    #[test]
    fn test_env_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert("server.host".to_string(), "0.0.0.0".to_string());
        env_vars.insert("server.port".to_string(), "443".to_string());
        env_vars.insert(
            "redis.uri".to_string(),
            "rediss://localhost:6379".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert_eq!(
            config.redis.unwrap().uri.expose_secret(),
            "rediss://localhost:6379"
        );
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
        assert!(config.redis.is_none());
    }
}
