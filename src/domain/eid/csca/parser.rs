use super::{CscaInfo, CscaLinkCertificate, CscaValidationError, MasterList};
use base64::Engine;
use openssl::x509::X509;
use quick_xml::de::from_str as xml_from_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;
use tracing::{info, warn};

/// Master List parser for different formats
pub struct MasterListParser;

/// Master List in LDIF (LDAP Data Interchange Format) - common ICAO format
#[derive(Debug, Serialize, Deserialize)]
pub struct LdifMasterList {
    pub version: String,
    pub issue_date: String,
    pub next_update: String,
    pub entries: Vec<LdifEntry>,
}

/// LDIF entry representing a CSCA certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct LdifEntry {
    pub country_code: String,
    pub certificate_type: String,
    pub certificate_data: String, // Base64 encoded DER
    pub subject_dn: Option<String>,
    pub issuer_dn: Option<String>,
}

/// Master List in JSON format for easier parsing
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonMasterList {
    pub version: String,
    pub issue_date: String,
    pub next_update: String,
    pub countries: HashMap<String, JsonCountryInfo>,
    pub link_certificates: Vec<JsonLinkCertificate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCountryInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    pub csca_certificates: Vec<JsonCertificate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonCertificate {
    pub certificate_data: String, // Base64 encoded DER
    pub fingerprint: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonLinkCertificate {
    pub source_country: String,
    pub target_country: String,
    pub certificate: JsonCertificate,
}

/// Master List in XML format - common ICAO format for BSI and other authorities
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "MasterList")]
pub struct XmlMasterList {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueDate")]
    pub issue_date: String,
    #[serde(rename = "NextUpdate")]
    pub next_update: String,
    #[serde(rename = "Countries")]
    pub countries: XmlCountries,
    #[serde(rename = "LinkCertificates", default)]
    pub link_certificates: Option<XmlLinkCertificates>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlCountries {
    #[serde(rename = "Country", default)]
    pub country: Vec<XmlCountryInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlCountryInfo {
    #[serde(rename = "CountryCode")]
    pub country_code: String,
    #[serde(rename = "CSCACertificates")]
    pub csca_certificates: XmlCscaCertificates,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlCscaCertificates {
    #[serde(rename = "Certificate", default)]
    pub certificate: Vec<XmlCertificate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlCertificate {
    #[serde(rename = "CertificateData")]
    pub certificate_data: String, // Base64 encoded DER
    #[serde(rename = "Fingerprint", default)]
    pub fingerprint: Option<String>,
    #[serde(rename = "Subject", default)]
    pub subject: Option<String>,
    #[serde(rename = "Issuer", default)]
    pub issuer: Option<String>,
    #[serde(rename = "NotBefore", default)]
    pub not_before: Option<String>,
    #[serde(rename = "NotAfter", default)]
    pub not_after: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlLinkCertificates {
    #[serde(rename = "LinkCertificate", default)]
    pub link_certificate: Vec<XmlLinkCertificate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XmlLinkCertificate {
    #[serde(rename = "SourceCountry")]
    pub source_country: String,
    #[serde(rename = "TargetCountry")]
    pub target_country: String,
    #[serde(rename = "Certificate")]
    pub certificate: XmlCertificate,
}

impl MasterListParser {
    /// Parse Master List from JSON format
    pub fn parse_json(json_data: &str) -> Result<MasterList, CscaValidationError> {
        let json_ml: JsonMasterList = serde_json::from_str(json_data)
            .map_err(|e| CscaValidationError::MasterListParse(format!("JSON parse error: {e}")))?;

        let issue_date = Self::parse_date(&json_ml.issue_date)?;
        let next_update = Self::parse_date(&json_ml.next_update)?;

        let mut master_list = MasterList::new(json_ml.version, issue_date, next_update);

        // Parse CSCA certificates by country
        for (country_code, country_info) in json_ml.countries {
            // Use the country_code from the field if present, otherwise use the HashMap key
            let actual_country_code = country_info
                .country_code
                .as_deref()
                .unwrap_or(&country_code);
            for json_cert in country_info.csca_certificates {
                let csca_info = Self::parse_json_certificate(&json_cert, actual_country_code)?;
                master_list.add_csca(country_code.clone(), csca_info);
            }
        }

        // Parse link certificates
        for json_link in json_ml.link_certificates {
            let cert_info =
                Self::parse_json_certificate(&json_link.certificate, &json_link.source_country)?;
            let link_cert = CscaLinkCertificate {
                source_country: json_link.source_country,
                target_country: json_link.target_country,
                certificate_info: cert_info,
            };
            master_list.add_link_certificate(link_cert);
        }

        Ok(master_list)
    }

    /// Parse Master List from LDIF format
    pub fn parse_ldif(ldif_data: &str) -> Result<MasterList, CscaValidationError> {
        let mut master_list_version = String::new();
        let mut issue_date = String::new();
        let mut next_update = String::new();
        let mut entries = Vec::new();

        let mut current_entry: Option<LdifEntry> = None;

        for line in ldif_data.lines() {
            let line = line.trim();
            if line.is_empty() {
                if let Some(entry) = current_entry.take() {
                    entries.push(entry);
                }
                continue;
            }

            if line.starts_with("version:") {
                master_list_version = line
                    .strip_prefix("version:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("issueDate:") {
                issue_date = line
                    .strip_prefix("issueDate:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("nextUpdate:") {
                next_update = line
                    .strip_prefix("nextUpdate:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("c:") {
                // Start new entry
                if let Some(entry) = current_entry.take() {
                    entries.push(entry);
                }
                let country_code = line.split(':').nth(1).unwrap_or("").trim().to_string();
                current_entry = Some(LdifEntry {
                    country_code,
                    certificate_type: String::new(),
                    certificate_data: String::new(),
                    subject_dn: None,
                    issuer_dn: None,
                });
            } else if line.starts_with("certificateType:") {
                if let Some(ref mut entry) = current_entry {
                    entry.certificate_type =
                        line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
            } else if line.starts_with("cACertificate::") {
                if let Some(ref mut entry) = current_entry {
                    entry.certificate_data =
                        line.split("::").nth(1).unwrap_or("").trim().to_string();
                }
            } else if line.starts_with("subject:") {
                if let Some(ref mut entry) = current_entry {
                    entry.subject_dn =
                        Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                }
            } else if line.starts_with("issuer:") {
                if let Some(ref mut entry) = current_entry {
                    entry.issuer_dn = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                }
            }
        }

        // Add last entry if exists
        if let Some(entry) = current_entry {
            entries.push(entry);
        }

        let parsed_issue_date = Self::parse_date(&issue_date)?;
        let parsed_next_update = Self::parse_date(&next_update)?;

        let mut master_list =
            MasterList::new(master_list_version, parsed_issue_date, parsed_next_update);

        // Convert LDIF entries to CSCA certificates
        for entry in entries {
            if entry.certificate_type.to_lowercase() == "csca" {
                let csca_info = Self::parse_ldif_certificate(&entry)?;
                master_list.add_csca(entry.country_code, csca_info);
            }
        }

        Ok(master_list)
    }

    /// Parse Master List from XML format
    pub fn parse_xml(xml_data: &str) -> Result<MasterList, CscaValidationError> {
        let xml_ml: XmlMasterList = xml_from_str(xml_data)
            .map_err(|e| CscaValidationError::MasterListParse(format!("XML parse error: {e}")))?;

        let issue_date = Self::parse_date(&xml_ml.issue_date)?;
        let next_update = Self::parse_date(&xml_ml.next_update)?;

        let mut master_list = MasterList::new(xml_ml.version, issue_date, next_update);

        // Parse CSCA certificates by country
        for country_info in xml_ml.countries.country {
            for xml_cert in country_info.csca_certificates.certificate {
                let csca_info = Self::parse_xml_certificate(&xml_cert, &country_info.country_code)?;
                master_list.add_csca(country_info.country_code.clone(), csca_info);
            }
        }

        // Parse link certificates if present
        if let Some(link_certs) = xml_ml.link_certificates {
            for xml_link in link_certs.link_certificate {
                let cert_info =
                    Self::parse_xml_certificate(&xml_link.certificate, &xml_link.source_country)?;
                let link_cert = CscaLinkCertificate {
                    source_country: xml_link.source_country,
                    target_country: xml_link.target_country,
                    certificate_info: cert_info,
                };
                master_list.add_link_certificate(link_cert);
            }
        }

        Ok(master_list)
    }

    /// Parse Master List from binary DER format
    pub fn parse_der(der_data: &[u8]) -> Result<MasterList, CscaValidationError> {
        // The .ml files from BSI contain ASN.1/DER encoded certificates
        // We need to parse the binary structure and extract individual certificates

        info!(
            "Attempting to parse binary DER format master list ({} bytes)",
            der_data.len()
        );

        // Create a basic master list with current date
        let now = OffsetDateTime::now_utc();
        let mut master_list = MasterList::new(
            "Binary-DER".to_string(),
            now,
            now + time::Duration::days(365), // Assume 1 year validity
        );

        // Try to find and parse X.509 certificates in the binary data
        let mut offset = 0;
        let mut cert_count = 0;

        while offset < der_data.len() {
            // Look for ASN.1 SEQUENCE tag (0x30) followed by length
            if offset + 1 >= der_data.len() || der_data[offset] != 0x30 {
                offset += 1;
                continue;
            }

            // Try to parse certificate at this offset
            match Self::try_parse_certificate_at_offset(der_data, offset) {
                Ok((cert_info, cert_size)) => {
                    // Add certificate to master list
                    // Use a generic country code since we can't determine it from binary data alone
                    let country_code = cert_info.country_code.clone();
                    master_list.add_csca(country_code, cert_info);
                    cert_count += 1;
                    offset += cert_size;

                    info!(
                        "Successfully parsed certificate #{} at offset {}",
                        cert_count,
                        offset - cert_size
                    );
                }
                Err(_) => {
                    offset += 1;
                }
            }

            // Safety check to prevent infinite loops
            if cert_count > 1000 {
                warn!("Reached maximum certificate limit (1000), stopping parsing");
                break;
            }
        }

        if cert_count == 0 {
            return Err(CscaValidationError::MasterListParse(
                "No valid certificates found in binary DER data".to_string(),
            ));
        }

        info!(
            "Successfully parsed {} certificates from binary DER format",
            cert_count
        );
        Ok(master_list)
    }

    /// Try to parse a certificate at the given offset in DER data
    fn try_parse_certificate_at_offset(
        der_data: &[u8],
        offset: usize,
    ) -> Result<(CscaInfo, usize), CscaValidationError> {
        if offset >= der_data.len() {
            return Err(CscaValidationError::MasterListParse(
                "Offset out of bounds".to_string(),
            ));
        }

        // Try different certificate sizes starting from a reasonable minimum
        let min_cert_size = 100;
        let max_cert_size = std::cmp::min(4096, der_data.len() - offset);

        for size in min_cert_size..=max_cert_size {
            if offset + size > der_data.len() {
                break;
            }

            let cert_bytes = &der_data[offset..offset + size];

            // Try to parse as X.509 certificate
            if let Ok(x509_cert) = X509::from_der(cert_bytes) {
                // Extract country code from certificate subject or use "XX" as default
                let country_code =
                    Self::extract_country_from_cert(&x509_cert).unwrap_or_else(|| "XX".to_string());

                match CscaInfo::from_x509(&x509_cert, country_code) {
                    Ok(cert_info) => {
                        return Ok((cert_info, size));
                    }
                    Err(_) => continue,
                }
            }
        }

        Err(CscaValidationError::MasterListParse(
            "No valid certificate found at offset".to_string(),
        ))
    }

    /// Extract country code from X.509 certificate subject
    fn extract_country_from_cert(cert: &X509) -> Option<String> {
        let subject = cert.subject_name();

        // Try to find country (C=) entry in subject
        for entry in subject.entries() {
            let nid = entry.object().nid();
            if nid == openssl::nid::Nid::COUNTRYNAME {
                if let Ok(country) = entry.data().as_utf8() {
                    return Some(country.to_string());
                }
            }
        }

        None
    }

    /// Parse a certificate from JSON format
    fn parse_json_certificate(
        json_cert: &JsonCertificate,
        country_code: &str,
    ) -> Result<CscaInfo, CscaValidationError> {
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&json_cert.certificate_data)
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Base64 decode error: {e}"))
            })?;

        let x509_cert = X509::from_der(&cert_der)?;
        CscaInfo::from_x509(&x509_cert, country_code.to_string())
    }

    /// Parse a certificate from LDIF format
    fn parse_ldif_certificate(entry: &LdifEntry) -> Result<CscaInfo, CscaValidationError> {
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&entry.certificate_data)
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Base64 decode error: {e}"))
            })?;

        let x509_cert = X509::from_der(&cert_der)?;
        CscaInfo::from_x509(&x509_cert, entry.country_code.clone())
    }

    /// Parse a certificate from XML format
    fn parse_xml_certificate(
        xml_cert: &XmlCertificate,
        country_code: &str,
    ) -> Result<CscaInfo, CscaValidationError> {
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&xml_cert.certificate_data)
            .map_err(|e| {
                CscaValidationError::MasterListParse(format!("Base64 decode error: {e}"))
            })?;

        let x509_cert = X509::from_der(&cert_der)?;
        CscaInfo::from_x509(&x509_cert, country_code.to_string())
    }

    /// Parse date string in various formats
    fn parse_date(date_str: &str) -> Result<OffsetDateTime, CscaValidationError> {
        // Try parsing ISO 8601 with Z suffix first
        if date_str.ends_with('Z') {
            if let Ok(date) = OffsetDateTime::parse(
                date_str,
                &time::format_description::well_known::Iso8601::DEFAULT,
            ) {
                return Ok(date);
            }
        }

        // Try different date formats commonly used in Master Lists
        let formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y%m%d%H%M%SZ",
            "%Y-%m-%d",
        ];

        for format in &formats {
            if let Ok(date) = time::PrimitiveDateTime::parse(
                date_str,
                &time::format_description::parse(format).unwrap(),
            ) {
                return Ok(date.assume_utc());
            }
        }

        Err(CscaValidationError::MasterListParse(format!(
            "Unable to parse date: {date_str}",
        )))
    }

    /// Auto-detect format and parse Master List
    pub fn parse_auto(data: &str) -> Result<MasterList, CscaValidationError> {
        let trimmed_data = data.trim_start();

        // Try JSON first
        if trimmed_data.starts_with('{') {
            return Self::parse_json(data);
        }

        // Check if it's HTML (not XML) - HTML typically starts with DOCTYPE or <html>
        if trimmed_data.starts_with('<') {
            // Check for HTML indicators
            if trimmed_data.to_lowercase().contains("<!doctype html")
                || trimmed_data.to_lowercase().contains("<html")
                || trimmed_data.to_lowercase().contains("<head>")
            {
                return Err(CscaValidationError::MasterListParse(
                    "Received HTML content instead of Master List - this suggests the download URL extraction failed".to_string(),
                ));
            }
            // It's likely XML, try parsing it
            return Self::parse_xml(data);
        }

        // Try LDIF
        if data.contains("dn:") || data.contains("version:") {
            return Self::parse_ldif(data);
        }

        Err(CscaValidationError::MasterListParse(
            "Unable to detect Master List format - supported formats: JSON, XML, LDIF".to_string(),
        ))
    }
}
