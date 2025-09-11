use super::{CscaInfo, CscaLinkCertificate, CscaValidationError, MasterList};
use base64::Engine;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

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
    pub country_code: String,
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
            for json_cert in country_info.csca_certificates {
                let csca_info = Self::parse_json_certificate(&json_cert, &country_code)?;
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
                master_list_version = line.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if line.starts_with("issueDate:") {
                issue_date = line.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if line.starts_with("nextUpdate:") {
                next_update = line.split(':').nth(1).unwrap_or("").trim().to_string();
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

    /// Parse Master List from binary DER format
    pub fn parse_der(_der_data: &[u8]) -> Result<MasterList, CscaValidationError> {
        Err(CscaValidationError::MasterListParse(
            "DER format parsing not implemented - use JSON or LDIF format".to_string(),
        ))
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

    /// Parse date string in various formats
    fn parse_date(date_str: &str) -> Result<OffsetDateTime, CscaValidationError> {
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
        // Try JSON first
        if data.trim_start().starts_with('{') {
            return Self::parse_json(data);
        }

        // Try LDIF
        if data.contains("dn:") || data.contains("version:") {
            return Self::parse_ldif(data);
        }

        Err(CscaValidationError::MasterListParse(
            "Unable to detect Master List format - supported formats: JSON, LDIF".to_string(),
        ))
    }
}
