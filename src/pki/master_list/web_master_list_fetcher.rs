use super::{CscaValidationError, MasterList, MasterListParser, ZipAdapter};
use super::{FetcherConfig, MasterListFetcher};
use crate::config::PkiConfig;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct WebMasterListFetcher {
    http_client: Client,
    master_list_config: PkiConfig,
}

impl WebMasterListFetcher {
    /// Create a new web-based master list fetcher
    pub fn new(
        config: FetcherConfig,
        master_list_config: PkiConfig,
    ) -> Result<Self, CscaValidationError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(false)
            .use_rustls_tls()
            .build()
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            http_client,
            master_list_config,
        })
    }

    /// Fetch master list from configured URL
    async fn fetch_from_configured_url(&self) -> Result<MasterList, CscaValidationError> {
        let url = &self.master_list_config.url;
        info!("Trying to fetch master list from: {}", url);

        match self.fetch_from_url(url).await {
            Ok(master_list) => {
                info!("Successfully fetched master list from: {}", url);
                Ok(master_list)
            }
            Err(e) => {
                warn!("Failed to fetch from {}: {}", url, e);
                Err(e)
            }
        }
    }

    /// Fetch master list from a specific URL (simplified)
    async fn fetch_from_url(&self, url: &str) -> Result<MasterList, CscaValidationError> {
        let response = self.http_client.get(url).send().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to fetch from {url}: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(CscaValidationError::MasterListParse(format!(
                "Server returned error {}: {}",
                response.status(),
                url
            )));
        }

        // Check if this is an HTML page that needs link extraction
        if url.ends_with(".html") {
            let html_content = response.text().await.map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to read HTML response: {e}"))
            })?;

            return ZipAdapter::process_html_for_master_list(&self.http_client, url, &html_content)
                .await;
        }

        // Handle direct binary/ZIP files
        let bytes = response.bytes().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to read response bytes: {e}"))
        })?;

        let extracted_bytes = ZipAdapter::extract_or_passthrough(bytes.to_vec())?;
        MasterListParser::parse_der(&extracted_bytes)
    }
}

#[async_trait]
impl MasterListFetcher for WebMasterListFetcher {
    async fn fetch(&self) -> Result<MasterList, CscaValidationError> {
        info!("Fetching master list from web source");
        self.fetch_from_configured_url().await
    }
}
