use tracing::{debug, warn};
use url::Url;
use x509_parser::prelude::*;

/// Extract CRL distribution points from a certificate
pub fn extract_crl_distribution_points(cert: &X509Certificate) -> Vec<String> {
    let mut distribution_points = Vec::new();

    // Look for CRL Distribution Points extension (OID: 2.5.29.31)
    for ext in cert.tbs_certificate.extensions() {
        if ext.oid == oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
            debug!("Found CRL Distribution Points extension, parsing...");

            // Parse using enhanced binary pattern matching
            let mut urls = extract_urls_from_der_data(ext.value);

            // Fallback: Extract URLs using regex pattern matching on raw data
            if urls.is_empty() {
                warn!("Binary parsing failed, using fallback regex method");
                urls = extract_urls_with_regex_fallback(ext.value);
            }

            // Filter and validate URLs
            for url in urls {
                if is_valid_crl_url(&url) {
                    debug!("Found valid CRL distribution point: {}", url);
                    distribution_points.push(url);
                } else {
                    warn!("Invalid or unsupported CRL URL format: {}", url);
                }
            }
        }
    }

    if distribution_points.is_empty() {
        debug!("No CRL distribution points found in certificate extensions");
    } else {
        debug!(
            "Found {} CRL distribution points",
            distribution_points.len()
        );
    }

    distribution_points
}

/// Extract URLs from DER-encoded extension data using binary pattern matching
fn extract_urls_from_der_data(der_data: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();

    let http_pattern = b"http://";
    let https_pattern = b"https://";

    // Search for HTTP patterns
    for (i, window) in der_data.windows(http_pattern.len()).enumerate() {
        if window == http_pattern
            && let Some(url) = extract_url_from_position(der_data, i)
        {
            urls.push(url);
        }
    }

    // Search for HTTPS patterns
    for (i, window) in der_data.windows(https_pattern.len()).enumerate() {
        if window == https_pattern
            && let Some(url) = extract_url_from_position(der_data, i)
        {
            urls.push(url);
        }
    }

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    urls.retain(|url| seen.insert(url.clone()));

    urls
}

/// Extract a complete URL starting from the given position in the DER data
fn extract_url_from_position(data: &[u8], start_pos: usize) -> Option<String> {
    let mut end_pos = start_pos;

    for &byte in &data[start_pos..] {
        // Stop at common DER structure bytes, control characters, or spaces
        if byte == 0x30
            || byte == 0x86
            || byte == 0x82
            || byte == 0x04
            || !(0x20..=0x7E).contains(&byte)
            || byte == b' '
        {
            break;
        }
        end_pos += 1;
    }

    if end_pos > start_pos
        && let Ok(url_str) = String::from_utf8(data[start_pos..end_pos].to_vec())
    {
        // Basic URL validation - must end with reasonable characters
        if url_str.len() > 10
            && (url_str.ends_with(".crl")
                || url_str.ends_with('/')
                || url_str.chars().last().is_some_and(|c| c.is_alphanumeric()))
        {
            return Some(url_str);
        }
    }

    None
}

/// Fallback method using regex pattern matching for URL extraction
fn extract_urls_with_regex_fallback(extension_data: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();

    // Convert extension data to string, handling potential binary data
    if let Ok(data_str) = String::from_utf8(extension_data.to_vec()) {
        let url_regex = regex::Regex::new(
            r"https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*[a-zA-Z0-9/]",
        )
        .unwrap();

        for cap in url_regex.captures_iter(&data_str) {
            if let Some(url_match) = cap.get(0) {
                let url = url_match.as_str().to_string();
                // Additional cleanup - remove any trailing DER artifacts
                let clean_url = url
                    .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.')
                    .to_string();
                if !clean_url.is_empty() {
                    urls.push(clean_url);
                }
            }
        }
    } else {
        debug!("Extension data is not valid UTF-8, searching for URL patterns in raw bytes");
        urls = extract_urls_from_der_data(extension_data);
    }

    urls
}

/// Validate that the extracted URL is suitable for CRL distribution
///
/// Enhanced security validation to prevent:
/// - Local file access
/// - Private network access
/// - Malformed URLs
pub fn is_valid_crl_url(url: &str) -> bool {
    // Basic URL validation - must be HTTP or HTTPS
    if url.len() < 10 || (!url.starts_with("http://") && !url.starts_with("https://")) {
        return false;
    }

    // Parse URL to ensure it's well-formed
    if let Ok(parsed_url) = Url::parse(url) {
        // Ensure it has a valid host
        if parsed_url.host().is_none() {
            return false;
        }

        // Security: Reject localhost and private IPs
        if let Some(host) = parsed_url.host_str() {
            let host_lower = host.to_lowercase();

            // Reject localhost
            if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
                warn!("Rejecting localhost CRL URL: {}", url);
                return false;
            }

            // Reject private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if host.starts_with("10.")
                || host.starts_with("192.168.")
                || (host.starts_with("172.")
                    && host
                        .split('.')
                        .nth(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .is_some_and(|n| (16..=31).contains(&n)))
            {
                warn!("Rejecting private IP CRL URL: {}", url);
                return false;
            }

            // Reject link-local addresses (169.254.0.0/16)
            if host.starts_with("169.254.") {
                warn!("Rejecting link-local CRL URL: {}", url);
                return false;
            }
        }

        // Additional checks for CRL-specific patterns
        let path = parsed_url.path().to_lowercase();

        // Be more restrictive - prefer .crl extension
        if path.ends_with(".crl") {
            return true;
        }

        // Also allow paths that clearly indicate CRL distribution
        if path.contains("crl") || path.ends_with('/') {
            return true;
        }

        // For security, reject URLs without clear CRL indicators
        warn!(
            "URL does not have .crl extension or clear CRL indicator: {}",
            url
        );
        false
    } else {
        false
    }
}
