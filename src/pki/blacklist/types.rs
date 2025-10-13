use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Reason for blacklisting a certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlacklistReason {
    /// Certificate compromised
    Compromised,
    /// Certificate fraudulently issued
    Fraudulent,
    /// Certificate revoked by issuer
    Revoked,
    /// Security vulnerability detected
    SecurityVulnerability,
    /// Administrative block
    Administrative,
    /// Other reason with description
    Other(String),
}

impl std::fmt::Display for BlacklistReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compromised => write!(f, "Certificate compromised"),
            Self::Fraudulent => write!(f, "Fraudulently issued"),
            Self::Revoked => write!(f, "Certificate revoked"),
            Self::SecurityVulnerability => write!(f, "Security vulnerability"),
            Self::Administrative => write!(f, "Administrative block"),
            Self::Other(desc) => write!(f, "Other: {}", desc),
        }
    }
}

/// Entry in the blacklist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    /// Serial number of the blacklisted certificate (hex encoded)
    pub serial_number: String,
    
    /// Issuer distinguished name (optional for additional validation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    
    /// Reason for blacklisting
    pub reason: BlacklistReason,
    
    /// Date when the certificate was added to the blacklist
    #[serde(with = "time::serde::rfc3339")]
    pub date_added: OffsetDateTime,
    
    /// Additional notes or description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl BlacklistEntry {
    /// Create a new blacklist entry
    pub fn new(serial_number: String, reason: BlacklistReason) -> Self {
        Self {
            serial_number,
            issuer: None,
            reason,
            date_added: OffsetDateTime::now_utc(),
            notes: None,
        }
    }

    /// Create a blacklist entry with issuer information
    pub fn with_issuer(
        serial_number: String,
        issuer: String,
        reason: BlacklistReason,
    ) -> Self {
        Self {
            serial_number,
            issuer: Some(issuer),
            reason,
            date_added: OffsetDateTime::now_utc(),
            notes: None,
        }
    }

    /// Add notes to the blacklist entry
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    /// Check if a certificate serial number matches this entry
    pub fn matches_serial(&self, serial: &[u8]) -> bool {
        let serial_hex = hex::encode(serial).to_lowercase();
        let entry_serial = self.serial_number.replace(":", "").to_lowercase();
        serial_hex == entry_serial
    }

    /// Check if a certificate matches this entry (serial + optional issuer)
    pub fn matches(&self, serial: &[u8], issuer: Option<&str>) -> bool {
        if !self.matches_serial(serial) {
            return false;
        }

        if let (Some(entry_issuer), Some(cert_issuer)) = (&self.issuer, issuer) {
            entry_issuer == cert_issuer
        } else {
            true
        }
    }
}

/// Container for blacklist entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blacklist {
    /// Version of the blacklist format
    pub version: String,
    
    /// Date when the blacklist was last updated
    #[serde(with = "time::serde::rfc3339")]
    pub last_updated: OffsetDateTime,
    
    /// List of blacklisted certificates
    pub entries: Vec<BlacklistEntry>,
}

impl Blacklist {
    /// Create a new empty blacklist
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            last_updated: OffsetDateTime::now_utc(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to the blacklist
    pub fn add_entry(&mut self, entry: BlacklistEntry) {
        self.entries.push(entry);
        self.last_updated = OffsetDateTime::now_utc();
    }

    /// Find an entry by serial number
    pub fn find_by_serial(&self, serial: &[u8]) -> Option<&BlacklistEntry> {
        self.entries.iter().find(|e| e.matches_serial(serial))
    }

    /// Check if a certificate is blacklisted
    pub fn is_blacklisted(&self, serial: &[u8], issuer: Option<&str>) -> Option<&BlacklistEntry> {
        self.entries.iter().find(|e| e.matches(serial, issuer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_entry_matches_serial() {
        let entry = BlacklistEntry::new(
            "01:23:45:67:89:ab:cd:ef".to_string(),
            BlacklistReason::Compromised,
        );

        // Test with colons
        assert!(entry.matches_serial(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));

        // Test without colons in entry
        let entry2 = BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        );
        assert!(entry2.matches_serial(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));
    }

    #[test]
    fn test_blacklist_entry_matches_with_issuer() {
        let entry = BlacklistEntry::with_issuer(
            "0123456789abcdef".to_string(),
            "CN=Test CA".to_string(),
            BlacklistReason::Fraudulent,
        );

        // Matches with correct issuer
        assert!(entry.matches(
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            Some("CN=Test CA")
        ));

        // Does not match with wrong issuer
        assert!(!entry.matches(
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            Some("CN=Other CA")
        ));
    }

    #[test]
    fn test_blacklist_operations() {
        let mut blacklist = Blacklist::new();
        
        let entry1 = BlacklistEntry::new(
            "0123456789abcdef".to_string(),
            BlacklistReason::Compromised,
        );
        
        blacklist.add_entry(entry1);
        assert_eq!(blacklist.entries.len(), 1);

        let serial = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert!(blacklist.find_by_serial(&serial).is_some());
        assert!(blacklist.is_blacklisted(&serial, None).is_some());
    }
}