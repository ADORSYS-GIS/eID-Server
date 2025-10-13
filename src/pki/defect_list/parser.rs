// File: src/pki/defect_list/parser.rs
// Fixed XML parsing with proper error handling

use super::error::DefectListError;
use super::types::DefectList;
use quick_xml::de::from_str;
use std::path::Path;
use tokio::fs;

/// Parse a defect list from XML format
pub async fn parse_defect_list_xml(content: &str) -> Result<DefectList, DefectListError> {
    let defect_list: DefectList = from_str(content)
        .map_err(|e| DefectListError::InvalidFormat(format!("Failed to parse XML: {}", e)))?;

    tracing::info!(
        "Parsed defect list with {} entries, last updated: {}",
        defect_list.entries.len(),
        defect_list.last_updated
    );

    Ok(defect_list)
}

/// Load a defect list from an XML file
pub async fn load_defect_list_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<DefectList, DefectListError> {
    let path = path.as_ref();
    tracing::info!("Loading defect list from: {}", path.display());

    let content = fs::read_to_string(path).await?;
    parse_defect_list_xml(&content).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_defect_list_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<DefectList>
    <version>1.0</version>
    <last_updated>2024-01-01T00:00:00Z</last_updated>
    <entries>
        <DefectEntry>
            <document_number>DOC123</document_number>
            <serial_number>0123456789abcdef</serial_number>
            <defect_type>manufacturing</defect_type>
            <date_discovered>2024-01-01T00:00:00Z</date_discovered>
            <severity>4</severity>
        </DefectEntry>
    </entries>
</DefectList>"#;

        let defect_list = parse_defect_list_xml(xml).await.unwrap();
        assert_eq!(defect_list.entries.len(), 1);
        assert_eq!(defect_list.version, "1.0");
    }
}