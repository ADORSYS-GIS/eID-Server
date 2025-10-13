use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Type of defect in a document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefectType {
    /// Manufacturing defect
    Manufacturing,
    /// Cryptographic weakness
    CryptographicWeakness,
    /// Invalid signature
    InvalidSignature,
    /// Expired or invalid validity period
    InvalidValidity,
    /// Missing required fields
    MissingFields,
    /// Incorrect encoding
    EncodingError,
    /// Non-compliant with standards
    NonCompliant,
    /// Data integrity issue
    DataIntegrity,
    /// Other defect with description
    Other(String),
}

impl std::fmt::Display for DefectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manufacturing => write!(f, "Manufacturing defect"),
            Self::CryptographicWeakness => write!(f, "Cryptographic weakness"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidValidity => write!(f, "Invalid validity period"),
            Self::MissingFields => write!(f, "Missing required fields"),
            Self::EncodingError => write!(f, "Encoding error"),
            Self::NonCompliant => write!(f, "Non-compliant with standards"),
            Self::DataIntegrity => write!(f, "Data integrity issue"),
            Self::Other(desc) => write!(f, "Other: {}", desc),
        }
    }
}

/// Entry in the defect list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectEntry {
    /// Document number or identifier
    pub document_number: String,
    
    /// Serial number of the certificate (hex encoded, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    
    /// Issuer distinguished name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    
    /// Type of defect
    pub defect_type: DefectType,
    
    /// Date when the defect was discovered
    #[serde(with = "time::serde::rfc3339")]
    pub date_discovered: OffsetDateTime,
    
    /// Severity level (1-5, with 5 being most severe)
    #[serde(default = "default_severity")]
    pub severity: u8,
    
    /// Additional description of the defect
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_severity() -> u8 {
    3
}

impl DefectEntry {
    /// Create a new defect entry
    pub fn new(document_number: String, defect_type: DefectType) -> Self {
        Self {
            document_number,
            serial_number: None,
            issuer: None,
            defect_type,
            date_discovered: OffsetDateTime::now_utc(),
            severity: default_severity(),
            description: None,
        }
    }

    /// Create a defect entry with serial number
    pub fn with_serial(
        document_number: String,
        serial_number: String,
        defect_type: DefectType,
    ) -> Self {
        Self {
            document_number,
            serial_number: Some(serial_number),
            issuer: None,
            defect_type,
            date_discovered: OffsetDateTime::now_utc(),
            severity: default_severity(),
            description: None,
        }
    }

    /// Set severity level
    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity.clamp(1, 5);
        self
    }

    /// Add description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Check if a certificate serial number matches this entry
    pub fn matches_serial(&self, serial: &[u8]) -> bool {
        if let Some(ref entry_serial) = self.serial_number {
            let serial_hex = hex::encode(serial).to_lowercase();
            let entry_serial_clean = entry_serial.replace(":", "").to_lowercase();
            serial_hex == entry_serial_clean
        } else {
            false
        }
    }

    /// Check if a document matches this entry
    pub fn matches(&self, serial: Option<&[u8]>, issuer: Option<&str>) -> bool {
        // Check serial number if provided
        if let Some(cert_serial) = serial {
            if self.serial_number.is_some() && !self.matches_serial(cert_serial) {
                return false;
            }
        }

        // Check issuer if both are provided
        if let (Some(entry_issuer), Some(cert_issuer)) = (&self.issuer, issuer) {
            if entry_issuer != cert_issuer {
                return false;
            }
        }

        true
    }
}

/// Container for defect list entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectList {
    /// Version of the defect list format
    pub version: String,
    
    /// Date when the defect list was last updated
    #[serde(with = "time::serde::rfc3339")]
    pub last_updated: OffsetDateTime,
    
    /// List of defective documents
    pub entries: Vec<DefectEntry>,
}

impl DefectList {
    /// Create a new empty defect list
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            last_updated: OffsetDateTime::now_utc(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to the defect list
    pub fn add_entry(&mut self, entry: DefectEntry) {
        self.entries.push(entry);
        self.last_updated = OffsetDateTime::now_utc();
    }

    /// Find entries by document number
    pub fn find_by_document_number(&self, doc_num: &str) -> Vec<&DefectEntry> {
        self.entries
            .iter()
            .filter(|e| e.document_number == doc_num)
            .collect()
    }

    /// Find an entry by serial number
    pub fn find_by_serial(&self, serial: &[u8]) -> Option<&DefectEntry> {
        self.entries.iter().find(|e| e.matches_serial(serial))
    }

    /// Check if a document has defects
    pub fn has_defects(&self, serial: Option<&[u8]>, issuer: Option<&str>) -> Option<&DefectEntry> {
        self.entries.iter().find(|e| e.matches(serial, issuer))
    }

    /// Get all entries with severity >= threshold
    pub fn get_by_severity(&self, min_severity: u8) -> Vec<&DefectEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defect_entry_matches_serial() {
        let entry = DefectEntry::with_serial(
            "DOC123".to_string(),
            "01:23:45:67:89:ab:cd:ef".to_string(),
            DefectType::Manufacturing,
        );

        assert!(entry.matches_serial(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));
        assert!(!entry.matches_serial(&[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    #[test]
    fn test_defect_entry_severity() {
        let entry = DefectEntry::new("DOC123".to_string(), DefectType::CryptographicWeakness)
            .with_severity(5);

        assert_eq!(entry.severity, 5);

        // Test clamping
        let entry2 = DefectEntry::new("DOC456".to_string(), DefectType::Manufacturing)
            .with_severity(10);
        assert_eq!(entry2.severity, 5);
    }

    #[test]
    fn test_defect_list_operations() {
        let mut defect_list = DefectList::new();
        
        let entry1 = DefectEntry::with_serial(
            "DOC123".to_string(),
            "0123456789abcdef".to_string(),
            DefectType::InvalidSignature,
        )
        .with_severity(4);
        
        defect_list.add_entry(entry1);
        assert_eq!(defect_list.entries.len(), 1);

        let docs = defect_list.find_by_document_number("DOC123");
        assert_eq!(docs.len(), 1);

        let severe = defect_list.get_by_severity(4);
        assert_eq!(severe.len(), 1);
    }
}