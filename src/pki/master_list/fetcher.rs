use crate::pki::truststore::CertificateEntry;
use color_eyre::eyre::Result;
use reqwest;
use scraper::{Html, Selector};
use std::io::Read;
use url::Url;
use zip::ZipArchive;

use super::MasterListError;

/// Master list fetcher for downloading and processing CSCA certificates
pub struct MasterListFetcher {
    client: reqwest::Client,
    url: String,
}

impl MasterListFetcher {
    /// Create a new master list fetcher with the specified URL
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    /// Fetch the master list from the configured URL
    pub async fn fetch_master_list(&self) -> Result<Vec<u8>, MasterListError> {
        // First, fetch the HTML page to find the actual ZIP download link
        let html_response = self.client.get(&self.url).send().await?.text().await?;

        // Extract the ZIP file URL from the HTML
        let zip_url = self.extract_zip_url_from_html(&html_response)?;

        // Download the ZIP file
        let zip_response = self.client.get(&zip_url).send().await?.bytes().await?;

        Ok(zip_response.to_vec())
    }

    /// Extract ZIP download URL from the HTML page using proper HTML parsing
    fn extract_zip_url_from_html(&self, html: &str) -> Result<String, MasterListError> {
        let document = Html::parse_document(html);
        let link_selector = match Selector::parse("a[href]") {
            Ok(selector) => selector,
            Err(e) => {
                return Err(MasterListError::Parser {
                    message: format!("CSS selector parsing error: {e}"),
                });
            }
        };

        let base_url = Url::parse("https://www.bsi.bund.de")?;

        // Look for ZIP file links
        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href")
                && href.contains(".zip")
            {
                // Parse the URL properly using the url crate
                let absolute_url = base_url.join(href)?;

                return Ok(absolute_url.to_string());
            }
        }

        Err(MasterListError::Parser {
            message: "Could not find ZIP download link in HTML".to_string(),
        })
    }

    /// Extract CSCA certificates from the master list ZIP file
    pub async fn extract_csca_certificates(
        &self,
        zip_data: Vec<u8>,
    ) -> Result<Vec<CertificateEntry>, MasterListError> {
        let cursor = std::io::Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor)?;
        let mut certificates = Vec::new();

        // Iterate through all files in the ZIP archive
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;

            // Look for certificate files (common extensions)
            let file_name = file.name().to_lowercase();
            if file_name.ends_with(".cer")
                || file_name.ends_with(".crt")
                || file_name.ends_with(".der")
            {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;

                // Try to parse as DER-encoded certificate
                match CertificateEntry::from_der(&contents) {
                    Ok(cert_entry) => {
                        certificates.push(cert_entry);
                    }
                    Err(_) => {
                        // If DER parsing fails, try PEM
                        if let Ok(pem_contents) = String::from_utf8(contents.clone())
                            && let Ok(pem_parsed) = pem::parse(&pem_contents)
                            && pem_parsed.tag() == "CERTIFICATE"
                            && let Ok(cert_entry) =
                                CertificateEntry::from_der(pem_parsed.contents())
                        {
                            certificates.push(cert_entry);
                        }
                    }
                }
            }
        }

        if certificates.is_empty() {
            return Err(MasterListError::NoValidCertificates);
        }

        Ok(certificates)
    }
}

impl Default for MasterListFetcher {
    fn default() -> Self {
        Self::new("".to_string()) // URL should be provided via configuration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_master_list_fetcher_creation() {
        let _fetcher = MasterListFetcher::default();
        // Just test that creation doesn't panic
    }

    #[tokio::test]
    async fn test_pem_parsing() {
        let pem_data = "-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKnL4UKMTVE/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMTEyMTAwNDIzMjlaFw0yMjEyMTAwNDIzMjlaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwofnLwqB
BnkqBUM4Ccvs4mrUsIiC9s4kk4aMTatXKzda1gauss4egatGdWxo29K3hl9BjC1/
PCOAlJCqNbqxl4X8W6P6E0m0wW8fg3I1cF9b0H7xMh5LaX3HMC7e9Zh36Y7XTDHX
TqS+l4jUjhc5e5W7ZzqGZ9Ie7VKV/MR8xVkCAwEAATANBgkqhkiG9w0BAQsFAAOB
gQCg3u4OoHw5GcZzrv9z7L1z5h4WDgCeV9Yr+uXH8VD9dw9o1rNQF3sMkz4h9K6j
7p3F5aMD0fT4L5oMp8QWxkMFJrDKl+hKg6Kv0VGJcFoGZf5mQD0Q
-----END CERTIFICATE-----";

        let result = pem::parse(pem_data);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.tag(), "CERTIFICATE");
    }
}
