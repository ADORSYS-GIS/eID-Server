use std::{collections::HashMap, time::Duration};

use config::{Config as ConfigLib, ConfigError, Environment, File};
use redis::{
    Client as RedisClient, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterListConfig {
    pub master_list_url: String,
}

impl Default for MasterListConfig {
    fn default() -> Self {
        Self {
            master_list_url: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlConfig {
    /// Enable CRL checking (default: true)
    #[serde(default = "default_crl_enabled")]
    pub enabled: bool,

    /// HTTP timeout for CRL fetching in seconds (default: 30)
    #[serde(default = "default_crl_timeout")]
    pub timeout_secs: u64,

    #[serde(default = "default_crl_fallback")]
    pub allow_fallback: bool,

    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,

    #[serde(default = "default_cache_cleanup")]
    pub cache_cleanup_interval_hours: u64,
}

fn default_crl_enabled() -> bool {
    true
}

fn default_crl_timeout() -> u64 {
    30
}

fn default_crl_fallback() -> bool {
    true
}

fn default_check_interval() -> u64 {
    24
}

fn default_cache_cleanup() -> u64 {
    12
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            enabled: default_crl_enabled(),
            timeout_secs: default_crl_timeout(),
            allow_fallback: default_crl_fallback(),
            check_interval_hours: default_check_interval(),
            cache_cleanup_interval_hours: default_cache_cleanup(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub redis: Option<RedisConfig>,
    pub master_list: MasterListConfig,
    #[serde(default)]
    pub crl: CrlConfig,
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
            .set_default("master_list.master_list_url", "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html")?
            // CRL defaults
            .set_default("crl.enabled", true)?
            .set_default("crl.timeout_secs", 30)?
            .set_default("crl.allow_fallback", true)?
            .set_default("crl.check_interval_hours", 24)?
            .set_default("crl.cache_cleanup_interval_hours", 12)?
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

        // Check CRL defaults
        assert!(config.crl.enabled);
        assert_eq!(config.crl.timeout_secs, 30);
        assert!(config.crl.allow_fallback);
        assert_eq!(config.crl.check_interval_hours, 24);
        assert_eq!(config.crl.cache_cleanup_interval_hours, 12);
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

    #[test]
    fn test_crl_config_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert("crl.enabled".to_string(), "false".to_string());
        env_vars.insert("crl.timeout_secs".to_string(), "60".to_string());
        env_vars.insert("crl.allow_fallback".to_string(), "false".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert!(!config.crl.enabled);
        assert_eq!(config.crl.timeout_secs, 60);
        assert!(!config.crl.allow_fallback);
    }

    #[test]
    fn test_crl_default_values() {
        let crl_config = CrlConfig::default();

        assert!(crl_config.enabled);
        assert_eq!(crl_config.timeout_secs, 30);
        assert!(crl_config.allow_fallback);
        assert_eq!(crl_config.check_interval_hours, 24);
        assert_eq!(crl_config.cache_cleanup_interval_hours, 12);
    }
}
