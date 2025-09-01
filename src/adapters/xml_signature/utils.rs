//! XML processing utilities for signature handling
//!
//! This module contains utility functions for XML processing including PEM parsing,
//! signature removal, and XML canonicalization.

use color_eyre::eyre::{self, Context, Result};
use pem;
use tracing::debug;
use xml_c14n::{self, CanonicalizationOptions};

/// Parse and validate PEM content with expected tags
pub fn parse_and_validate_pem(pem_data: &[u8], expected_tags: &[&str]) -> Result<pem::Pem> {
    if expected_tags.is_empty() {
        return Err(eyre::eyre!("At least one expected tag must be provided"));
    }

    let pem = pem::parse(pem_data).with_context(|| "Failed to parse PEM content")?;

    if !expected_tags.contains(&pem.tag()) {
        return Err(eyre::eyre!(
            "Expected one of {:?} in PEM, found: {}",
            expected_tags,
            pem.tag()
        ));
    }

    Ok(pem)
}

/// Remove signature elements from XML (improved enveloped-signature transform)
pub fn remove_signatures_from_xml(xml: &str) -> Result<String> {
    debug!("Removing signature elements from XML using improved string processing");

    let mut result = xml.to_string();

    // Keep removing signatures until none are found (handles nested cases)
    loop {
        let original_len = result.len();

        // Find signature start with namespace awareness
        if let Some(start) = result.find("<Signature") {
            // Find the matching end tag, accounting for nested elements
            let mut depth = 0;
            let mut pos = start;
            let mut found_end = false;

            while pos < result.len() {
                if let Some(tag_start) = result[pos..].find('<') {
                    pos += tag_start;

                    if result[pos..].starts_with("<Signature") {
                        depth += 1;
                    } else if result[pos..].starts_with("</Signature>") {
                        depth -= 1;
                        if depth == 0 {
                            let end_pos = pos + "</Signature>".len();
                            result.replace_range(start..end_pos, "");
                            found_end = true;
                            break;
                        }
                    }
                    pos += 1;
                } else {
                    break;
                }
            }

            if !found_end {
                // If we couldn't find a proper end tag, fall back to simple removal
                if let Some(end) = result[start..].find("</Signature>") {
                    let end_pos = start + end + "</Signature>".len();
                    result.replace_range(start..end_pos, "");
                } else {
                    break; // No more signatures to remove
                }
            }
        } else {
            break; // No more signatures found
        }

        // If no changes were made, break to avoid infinite loop
        if result.len() == original_len {
            break;
        }
    }

    Ok(result)
}

/// Canonicalize XML using proper C14N library (xml_c14n crate)
pub fn canonicalize_xml(xml: &str) -> Result<String> {
    debug!("Canonicalizing XML using proper C14N library (xml_c14n crate)");

    // that were originally signed, following the canonical XML specification
    let options = CanonicalizationOptions::default();
    xml_c14n::canonicalize_xml(xml, options)
        .with_context(|| "Failed to canonicalize XML using C14N")
}
