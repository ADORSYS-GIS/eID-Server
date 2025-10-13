use super::error::BlacklistError;
use super::types::Blacklist;
use std::path::Path;
use tokio::fs;

/// Parse a blacklist from JSON format
pub async fn parse_blacklist_json(content: &str) -> Result<Blacklist, BlacklistError> {
    let blacklist: Blacklist = serde_json::from_str(content)
        .map_err(|e| BlacklistError::InvalidFormat(format!("Failed to parse JSON: {}", e)))?;

    tracing::info!(
        "Parsed blacklist with {} entries, last updated: {}",
        blacklist.entries.len(),
        blacklist.last_updated
    );

    Ok(blacklist)
}

/// Load a blacklist from a JSON file
pub async fn load_blacklist_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Blacklist, BlacklistError> {
    let path = path.as_ref();
    tracing::info!("Loading blacklist from: {}", path.display());

    let content = fs::read_to_string(path).await?;
    parse_blacklist_json(&content).await
}

/// Parse blacklist from CSV format
/// CSV format: serial_number,issuer,reason,date_added,notes
pub async fn parse_blacklist_csv(content: &str) -> Result<Blacklist, BlacklistError> {
    use super::types::{BlacklistEntry, BlacklistReason};
    use time::OffsetDateTime;

    let mut blacklist = Blacklist::new();
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(content.as_bytes());

    for result in reader.records() {
        let record = result.map_err(|e| {
            BlacklistError::InvalidFormat(format!("Failed to parse CSV record: {}", e))
        })?;

        if record.len() < 3 {
            continue; // Skip invalid records
        }

        let serial_number = record.get(0).unwrap_or("").trim().to_string();
        let issuer = record.get(1).and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let reason = match record.get(2).unwrap_or("").trim().to_lowercase().as_str() {
            "compromised" => BlacklistReason::Compromised,
            "fraudulent" => BlacklistReason::Fraudulent,
            "revoked" => BlacklistReason::Revoked,
            "security_vulnerability" => BlacklistReason::SecurityVulnerability,
            "administrative" => BlacklistReason::Administrative,
            other => BlacklistReason::Other(other.to_string()),
        };

        let date_added = if let Some(date_str) = record.get(3) {
            OffsetDateTime::parse(date_str.trim(), &time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| OffsetDateTime::now_utc())
        } else {
            OffsetDateTime::now_utc()
        };

        let notes = record.get(4).and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let mut entry = BlacklistEntry {
            serial_number,
            issuer,
            reason,
            date_added,
            notes: None,
        };

        if let Some(n) = notes {
            entry = entry.with_notes(n);
        }

        blacklist.add_entry(entry);
    }

    tracing::info!("Parsed {} blacklist entries from CSV", blacklist.entries.len());
    Ok(blacklist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_blacklist_json() {
        let json = r#"{
            "version": "1.0",
            "last_updated": "2024-01-01T00:00:00Z",
            "entries": [
                {
                    "serial_number": "0123456789abcdef",
                    "reason": "compromised",
                    "date_added": "2024-01-01T00:00:00Z"
                }
            ]
        }"#;

        let blacklist = parse_blacklist_json(json).await.unwrap();
        assert_eq!(blacklist.entries.len(), 1);
        assert_eq!(blacklist.version, "1.0");
    }

    #[tokio::test]
    async fn test_parse_blacklist_csv() {
        let csv = "serial_number,issuer,reason,date_added,notes
0123456789abcdef,CN=Test CA,compromised,2024-01-01T00:00:00Z,Test note
fedcba9876543210,,fraudulent,2024-01-01T00:00:00Z,";

        let blacklist = parse_blacklist_csv(csv).await.unwrap();
        assert_eq!(blacklist.entries.len(), 2);
    }
}