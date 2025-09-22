use super::{CscaValidationError, MasterList, MasterListParser};
use regex::Regex;
use reqwest::Client;
use std::io::{Cursor, Read};
use std::sync::LazyLock;
use tracing::{debug, warn};
use zip::ZipArchive;

/// Lazy-initialized regex for finding ZIP download links in HTML
static ZIP_LINK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"href="([^"]*\.zip[^"]*)"#).expect("Invalid regex pattern for ZIP links")
});

/// Adapter for handling zip-compressed master list files
pub struct ZipAdapter;

impl ZipAdapter {
    /// Check if the data appears to be a zip file by examining magic bytes
    pub fn is_zip_file<T: AsRef<[u8]>>(data: T) -> bool {
        let data = data.as_ref();
        // ZIP file magic bytes: PK (0x504B)
        data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4B
    }

    /// Extract the first file from a zip archive
    /// Returns the extracted bytes or the original data if not a zip file
    pub fn extract_or_passthrough<T: Into<Vec<u8>>>(
        data: T,
    ) -> Result<Vec<u8>, CscaValidationError> {
        let data = data.into();
        if !Self::is_zip_file(&data) {
            debug!("Data is not a zip file, passing through unchanged");
            return Ok(data);
        }

        debug!("Detected zip file, attempting to extract contents");
        Self::extract_first_file(data)
    }

    /// Extract the first file from a zip archive
    fn extract_first_file(data: Vec<u8>) -> Result<Vec<u8>, CscaValidationError> {
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)?;

        if archive.is_empty() {
            return Err(CscaValidationError::MasterListParse(
                "Zip archive is empty".to_string(),
            ));
        }

        // Get the first file in the archive
        let mut file = archive.by_index(0)?;

        let file_name = file.name().to_string();
        debug!("Extracting file: {} ({} bytes)", file_name, file.size());

        // Read the file contents
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        debug!(
            "Successfully extracted {} bytes from {}",
            contents.len(),
            file_name
        );
        Ok(contents)
    }

    /// Extract a specific file from a zip archive by name
    /// Falls back to extracting the first file if the specific file is not found
    pub fn extract_file_by_name<T: Into<Vec<u8>>, S: AsRef<str>>(
        data: T,
        target_filename: S,
    ) -> Result<Vec<u8>, CscaValidationError> {
        let data = data.into();
        let target_filename = target_filename.as_ref();
        if !Self::is_zip_file(&data) {
            debug!("Data is not a zip file, passing through unchanged");
            return Ok(data);
        }

        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)?;

        // Try to find the specific file first
        let mut target_index = None;
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;

            let file_name = file.name();
            if file_name.contains(target_filename) || file_name.ends_with(target_filename) {
                debug!("Found target file: {} in zip archive", file_name);
                target_index = Some(i);
                break;
            }
        }

        let index_to_extract = target_index.unwrap_or_else(|| {
            warn!(
                "Target file '{}' not found in zip, extracting first file instead",
                target_filename
            );
            0
        });

        if archive.is_empty() {
            return Err(CscaValidationError::MasterListParse(
                "Zip archive is empty".to_string(),
            ));
        }

        let mut file = archive.by_index(index_to_extract)?;

        let file_name = file.name().to_string();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        debug!(
            "Successfully extracted {} bytes from {}",
            contents.len(),
            file_name
        );
        Ok(contents)
    }

    /// Process HTML content to extract ZIP download link and fetch the master list
    pub async fn process_html_for_master_list<U: AsRef<str>, H: AsRef<str>>(
        http_client: &Client,
        _url: U,
        html_content: H,
    ) -> Result<MasterList, CscaValidationError> {
        let _url = _url.as_ref();
        let html_content = html_content.as_ref();
        // Use lazy-initialized regex to find ZIP download link
        if let Some(captures) = ZIP_LINK_REGEX.captures(html_content)
            && let Some(link) = captures.get(1)
        {
            let download_url = if link.as_str().starts_with("http") {
                link.as_str().to_string()
            } else {
                format!("https://www.bsi.bund.de{}", link.as_str())
            };

            // Fetch the actual ZIP file
            let zip_response = http_client.get(&download_url).send().await?;

            let bytes = zip_response.bytes().await?;

            let extracted_bytes = Self::extract_or_passthrough(bytes.to_vec())?;
            return MasterListParser::parse_der(&extracted_bytes);
        }

        Err(CscaValidationError::MasterListParse(
            "No ZIP download link found in HTML".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zip_file() {
        // Valid zip magic bytes
        let zip_data = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        assert!(ZipAdapter::is_zip_file(&zip_data));

        // Invalid zip magic bytes
        let non_zip_data = vec![0x30, 0x82, 0x01, 0x02];
        assert!(!ZipAdapter::is_zip_file(&non_zip_data));

        // Empty data
        let empty_data = vec![];
        assert!(!ZipAdapter::is_zip_file(&empty_data));

        // Too short data
        let short_data = vec![0x50];
        assert!(!ZipAdapter::is_zip_file(&short_data));
    }

    #[test]
    fn test_extract_or_passthrough_non_zip() {
        let non_zip_data = vec![0x30, 0x82, 0x01, 0x02, 0xFF, 0xEE];
        let result = ZipAdapter::extract_or_passthrough(non_zip_data.clone()).unwrap();
        assert_eq!(result, non_zip_data);
    }
}
