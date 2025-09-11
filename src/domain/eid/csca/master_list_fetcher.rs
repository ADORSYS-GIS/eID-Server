use super::{CscaValidationError, MasterList, MasterListParser};
use regex::Regex;
use reqwest::Client;
use std::io::{Cursor, Read};
use std::time::Duration;
use tracing::{info, warn};
use zip::ZipArchive;

/// Service for fetching Master Lists from remote sources
#[derive(Debug, Clone)]
pub struct MasterListFetcher {
    http_client: Client,
}

impl MasterListFetcher {
    /// Create a new Master List fetcher
    pub fn new() -> Result<Self, CscaValidationError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("eID-Server/0.1.0")
            .build()
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { http_client })
    }

    /// Fetch and load German Master List from BSI website
    pub async fn fetch_german_master_list(&self) -> Result<MasterList, CscaValidationError> {
        const BSI_MASTER_LIST_URL: &str = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html";

        info!("Fetching German Master List from BSI website");

        // First, fetch the HTML page to find the actual Master List download link
        let html_response = self
            .http_client
            .get(BSI_MASTER_LIST_URL)
            .send()
            .await
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to fetch BSI page: {e}"))
            })?;

        if !html_response.status().is_success() {
            return Err(CscaValidationError::MasterListParse(format!(
                "BSI website returned error: {}",
                html_response.status()
            )));
        }

        let html_content = html_response.text().await.map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to read BSI page content: {e}"))
        })?;

        // Parse HTML to find the Master List download link
        let download_url = self.extract_master_list_download_url(&html_content)?;

        info!("Found Master List download URL: {}", download_url);

        // Download the actual Master List file
        let master_list_response =
            self.http_client
                .get(&download_url)
                .send()
                .await
                .map_err(|e| {
                    CscaValidationError::MasterListParse(format!(
                        "Failed to download Master List: {e}"
                    ))
                })?;

        if !master_list_response.status().is_success() {
            return Err(CscaValidationError::MasterListParse(format!(
                "Master List download failed: {}",
                master_list_response.status()
            )));
        }

        // Check if the downloaded file is a ZIP
        if download_url.ends_with(".zip") {
            info!("Downloaded ZIP file, extracting content");

            let master_list_bytes = master_list_response.bytes().await.map_err(|e| {
                CscaValidationError::MasterListParse(format!(
                    "Failed to read Master List bytes: {e}"
                ))
            })?;

            // Extract the master list from ZIP
            let extracted_content =
                self.extract_master_list_from_zip(master_list_bytes.as_ref())?;

            // Try to parse as binary ASN.1/DER format first, then fallback to text parsing
            match MasterListParser::parse_der(&extracted_content) {
                Ok(master_list) => Ok(master_list),
                Err(_) => {
                    // Fallback to text parsing if DER parsing fails
                    let text_content = String::from_utf8(extracted_content).map_err(|e| {
                        CscaValidationError::MasterListParse(format!(
                            "Failed to convert extracted content to UTF-8: {e}"
                        ))
                    })?;
                    MasterListParser::parse_auto(&text_content)
                }
            }
        } else {
            // Handle non-ZIP files as before
            let master_list_content = master_list_response.text().await.map_err(|e| {
                CscaValidationError::MasterListParse(format!(
                    "Failed to read Master List content: {e}"
                ))
            })?;

            info!("Downloaded Master List, parsing content");

            // Parse the downloaded Master List
            MasterListParser::parse_auto(&master_list_content)
        }
    }

    /// Extract Master List download URL from BSI HTML page
    fn extract_master_list_download_url(
        &self,
        html_content: &str,
    ) -> Result<String, CscaValidationError> {
        // Look for common patterns in BSI download links - updated for modern BSI website
        let patterns = [
            // Look for .ml files (binary master list format)
            r#"href="([^"]*\.ml[^"]*)"#,
            // Look for ZIP files containing master lists
            r#"href="([^"]*\.zip[^"]*)"#,
            // Look for LDIF files
            r#"href="([^"]*\.ldif[^"]*)"#,
            // Look for XML files
            r#"href="([^"]*\.xml[^"]*)"#,
            // Look for files with "MasterList" in name
            r#"href="([^"]*MasterList[^"]*)"#,
            // Look for files with "CSCA" in name
            r#"href="([^"]*CSCA[^"]*\.[a-zA-Z0-9]+)"#,
            // Look for German Master List specific patterns
            r#"href="([^"]*German[^"]*Master[^"]*)"#,
            // Look for download links in data attributes (modern web patterns)
            r#"data-download[^=]*="([^"]*\.[a-zA-Z0-9]+)"#,
        ];

        info!("Searching for master list download URL in HTML content");
        for (i, pattern) in patterns.iter().enumerate() {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(html_content) {
                    if let Some(url) = captures.get(1) {
                        let mut download_url = url.as_str().to_string();

                        // Convert relative URLs to absolute
                        if download_url.starts_with("/") {
                            download_url = format!("https://www.bsi.bund.de{download_url}");
                        } else if !download_url.starts_with("http") {
                            download_url = format!(
                                "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/{download_url}",
                            );
                        }

                        info!(
                            "Found download URL using pattern #{}: {}",
                            i + 1,
                            download_url
                        );
                        return Ok(download_url);
                    }
                }
            }
        }

        // Log HTML content for debugging if no patterns match
        warn!("Could not find master list download URL in HTML content");
        info!(
            "HTML content preview (first 500 chars): {}",
            &html_content.chars().take(500).collect::<String>()
        );

        // Enhanced fallback: try multiple common German Master List file names
        let fallback_urls = [
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.ml",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/MasterList.ml",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.ldif",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.xml",
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/MasterList.ldif",
        ];

        warn!("Using fallback URLs, trying first: {}", fallback_urls[0]);
        Ok(fallback_urls[0].to_string()) // Return first fallback
    }

    /// Extract master list content from ZIP archive
    fn extract_master_list_from_zip(
        &self,
        zip_data: &[u8],
    ) -> Result<Vec<u8>, CscaValidationError> {
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).map_err(|e| {
            CscaValidationError::MasterListParse(format!("Failed to open ZIP archive: {e}"))
        })?;

        // Look for master list files (typically .ml, .ldif, .xml)
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                CscaValidationError::MasterListParse(format!("Failed to access ZIP entry {i}: {e}"))
            })?;

            let file_name = file.name().to_lowercase();

            // Check if this is a master list file
            if file_name.ends_with(".ml")
                || file_name.ends_with(".ldif")
                || file_name.ends_with(".xml")
                || file_name.contains("masterlist")
                || file_name.contains("csca")
            {
                info!("Extracting master list file: {}", file.name());

                let mut content = Vec::new();
                file.read_to_end(&mut content).map_err(|e| {
                    CscaValidationError::MasterListParse(format!(
                        "Failed to read ZIP entry content: {e}"
                    ))
                })?;

                return Ok(content);
            }
        }

        Err(CscaValidationError::MasterListParse(
            "No master list file found in ZIP archive".to_string(),
        ))
    }
}

impl Default for MasterListFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create default Master List fetcher")
    }
}
