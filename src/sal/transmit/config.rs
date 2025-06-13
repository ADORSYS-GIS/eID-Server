use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TransmitConfig {
    /// URL of the eID-Client for APDU communication
    pub client_url: String,
    /// Maximum size of APDU messages in bytes
    pub max_apdu_size: usize,
    /// Session timeout in seconds
    pub session_timeout_secs: u32,
    /// Allowed TLS cipher suites
    pub allowed_cipher_suites: Vec<String>,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        Self {
            client_url: "http://127.0.0.1:24727/eID-Client".to_string(),
            max_apdu_size: 4096,
            session_timeout_secs: 30,
            allowed_cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransmitConfig::default();
        assert_eq!(config.max_apdu_size, 4096);
        assert_eq!(config.session_timeout_secs, 30);
        assert_eq!(config.client_url, "http://127.0.0.1:24727/eID-Client");
        assert!(!config.allowed_cipher_suites.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let mut config = TransmitConfig::default();
        assert!(config.validate().is_ok());

        config.client_url = String::new();
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.max_apdu_size = 0;
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.session_timeout_secs = 0;
        assert!(config.validate().is_err());

        config = TransmitConfig::default();
        config.allowed_cipher_suites.clear();
        assert!(config.validate().is_err());
    }
}
