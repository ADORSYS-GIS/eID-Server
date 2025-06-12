use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransmitConfig {
    /// Maximum size of APDU in bytes
    pub max_apdu_size: usize,

    /// Session timeout duration
    pub session_timeout: Duration,

    /// Maximum number of requests allowed per minute
    pub max_requests_per_minute: u32,

    /// Allowed cipher suites for TLS
    pub allowed_cipher_suites: Vec<String>,

    /// Whether client certificate is required
    pub require_client_certificate: bool,

    /// Minimum TLS version required
    pub min_tls_version: String,

    /// Client URL for classical systems
    pub client_url: String,

    /// Mobile client URL scheme
    pub mobile_client_url: String,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        Self {
            max_apdu_size: 4096,                       // 4KB default
            session_timeout: Duration::from_secs(300), // 5 minutes
            max_requests_per_minute: 60,
            allowed_cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
            ],
            require_client_certificate: true,
            min_tls_version: "TLSv1.2".to_string(),
            client_url: "http://127.0.0.1:24727/eID-Client".to_string(),
            mobile_client_url: "eid://127.0.0.1:24727/eID-Client".to_string(),
        }
    }
}

impl TransmitConfig {
    /// Validates the configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.max_apdu_size == 0 {
            return Err("max_apdu_size must be greater than 0".to_string());
        }

        if self.session_timeout.as_secs() == 0 {
            return Err("session_timeout must be greater than 0".to_string());
        }

        if self.max_requests_per_minute == 0 {
            return Err("max_requests_per_minute must be greater than 0".to_string());
        }

        if self.allowed_cipher_suites.is_empty() {
            return Err("at least one cipher suite must be specified".to_string());
        }

        if self.client_url.is_empty() {
            return Err("client_url must be specified".to_string());
        }

        if self.mobile_client_url.is_empty() {
            return Err("mobile_client_url must be specified".to_string());
        }

        Ok(())
    }

    /// Returns the appropriate client URL based on the platform
    pub fn get_client_url(&self) -> String {
        if cfg!(target_os = "android") || cfg!(target_os = "ios") {
            self.mobile_client_url.clone()
        } else {
            self.client_url.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransmitConfig::default();
        assert_eq!(config.max_apdu_size, 4096);
        assert_eq!(config.session_timeout.as_secs(), 300);
        assert_eq!(config.max_requests_per_minute, 60);
        assert!(!config.allowed_cipher_suites.is_empty());
        assert!(config.require_client_certificate);
        assert_eq!(config.min_tls_version, "TLSv1.2");
        assert_eq!(config.client_url, "http://127.0.0.1:24727/eID-Client");
        assert_eq!(config.mobile_client_url, "eid://127.0.0.1:24727/eID-Client");
    }

    #[test]
    fn test_config_validation() {
        let mut config = TransmitConfig::default();
        assert!(config.validate().is_ok());

        config.max_apdu_size = 0;
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.session_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.max_requests_per_minute = 0;
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.allowed_cipher_suites.clear();
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.client_url = String::new();
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.mobile_client_url = String::new();
        assert!(config.validate().is_err());
    }
}
