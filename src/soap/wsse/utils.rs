use crate::soap::wsse::{Error, Result};
use quick_xml::{Reader, Writer, events::Event};
use std::collections::HashMap;
use std::io::Cursor;

/// Insert an attribute into an element
pub fn insert_attributes(xml: &str, name: &str, attrs: Vec<(&str, &str)>) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut found = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().local_name().as_ref() == name.as_bytes() && !found => {
                found = true;
                let mut elem = e.to_owned();
                for attr in &attrs {
                    elem.push_attribute(*attr);
                }
                writer.write_event(Event::Start(elem))?;
            }
            Ok(Event::Eof) => break,
            Ok(e) => writer.write_event(e)?,
            Err(e) => return Err(Error::Xml(e.to_string())),
        }
        buf.clear();
    }
    if !found {
        return Err(Error::Xml(format!("No element '{name}' found in envelope")));
    }
    Ok(String::from_utf8(writer.into_inner())?)
}

/// Extract element by ID attribute
pub fn extract_element_by_id(xml: &str, id: &str) -> Result<String> {
    extract_with_predicate(xml, |e| {
        e.attributes().filter_map(|a| a.ok()).any(|attr| {
            let attr_key_val = attr.key.local_name();
            let key = attr_key_val.as_ref();
            key == b"Id" && attr.unescape_value().ok().as_deref() == Some(id)
        })
    })
    .map_err(|error| {
        if matches!(error, Error::Xml(ref msg) if msg == "Element not found") {
            Error::Xml(format!("Element with Id='{id}' not found in envelope"))
        } else {
            error
        }
    })
}

/// Extract element by local name
pub fn extract_element(xml: &str, name: &str) -> Result<String> {
    let target = name.as_bytes();
    extract_with_predicate(xml, |e| e.name().local_name().as_ref() == target).map_err(|error| {
        if matches!(error, Error::Xml(ref msg) if msg == "Element not found") {
            Error::Xml(format!("Element '{name}' not found in envelope"))
        } else {
            error
        }
    })
}

/// Extract element by predicate
fn extract_with_predicate<F>(xml: &str, mut predicate: F) -> Result<String>
where
    F: FnMut(&quick_xml::events::BytesStart) -> bool,
{
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut depth = 0;
    let mut capturing = false;

    // Track namespace declarations from parent elements
    let mut parent_namespaces: HashMap<String, String> = HashMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if !capturing && predicate(&e) {
                    capturing = true;
                    depth = 1;

                    // Create the target element with all parent namespaces
                    let mut target_elem = e.to_owned();

                    // Collect existing namespace declarations in the target element
                    let mut existing_namespaces: HashMap<String, String> = HashMap::new();
                    for attr in target_elem.attributes().with_checks(false).flatten() {
                        let key = attr.key.as_ref();
                        if key == b"xmlns" {
                            if let Ok(value) = attr.unescape_value() {
                                existing_namespaces.insert(String::new(), value.to_string());
                            }
                        } else if key.starts_with(b"xmlns:") {
                            let prefix = String::from_utf8_lossy(&key[6..]).to_string();
                            if let Ok(value) = attr.unescape_value() {
                                existing_namespaces.insert(prefix, value.to_string());
                            }
                        }
                    }

                    // Add parent namespace declarations only if they don't already exist
                    for (prefix, uri) in &parent_namespaces {
                        if !existing_namespaces.contains_key(prefix) {
                            if prefix.is_empty() {
                                target_elem.push_attribute(("xmlns", uri.as_str()));
                            } else {
                                let attr_name = format!("xmlns:{prefix}");
                                target_elem.push_attribute((attr_name.as_str(), uri.as_str()));
                            }
                        }
                    }
                    writer.write_event(Event::Start(target_elem))?;
                } else if capturing {
                    depth += 1;
                    writer.write_event(Event::Start(e))?;
                } else {
                    // Collect namespace declarations from parent elements
                    for attr in e.attributes().with_checks(false).flatten() {
                        let key = attr.key.as_ref();
                        if key == b"xmlns" {
                            if let Ok(value) = attr.unescape_value() {
                                parent_namespaces.insert(String::new(), value.to_string());
                            }
                        } else if key.starts_with(b"xmlns:") {
                            let prefix = String::from_utf8_lossy(&key[6..]).to_string();
                            if let Ok(value) = attr.unescape_value() {
                                parent_namespaces.insert(prefix, value.to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                if capturing {
                    writer.write_event(Event::End(e))?;
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(e) => {
                if capturing {
                    writer.write_event(e)?;
                }
            }
            Err(e) => return Err(Error::Xml(e.to_string())),
        }
        buf.clear();
    }

    if !capturing {
        return Err(Error::Xml("Element not found".into()));
    }
    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_element_by_id() {
        let xml = r#"<root><Body wsu:Id="body-123">content</Body></root>"#;
        let result = extract_element_by_id(xml, "body-123");
        assert!(result.is_ok());
        let element = result.unwrap();
        assert_eq!(element, "<Body wsu:Id=\"body-123\">content</Body>");
    }

    #[test]
    fn test_extract_security_header() {
        let envelope = r#"<?xml version="1.0"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Header>
                    <wsse:Security xmlns:wsse="http://example.com">
                        <wsu:Timestamp wsu:Id="TS-1">
                            <wsu:Created>2024-01-01T00:00:00Z</wsu:Created>
                            <wsu:Expires>2024-01-01T00:05:00Z</wsu:Expires>
                        </wsu:Timestamp>
                    </wsse:Security>
                </soapenv:Header>
                <soapenv:Body>
                    <test>content</test>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        // Extract Security header
        let result = extract_element(envelope, "Security");
        assert!(result.is_ok());
        let security = result.unwrap();
        assert!(security.contains("Security"));
        assert!(security.contains("Timestamp"));
    }

    #[test]
    fn test_add_body_id_to_envelope() {
        let xml = r#"<root><Body>content</Body></root>"#;
        let result = insert_attributes(xml, "Body", vec![("wsu:Id", "body-123")]);
        assert!(result.is_ok());
        let envelope = result.unwrap();
        assert_eq!(
            envelope,
            "<root><Body wsu:Id=\"body-123\">content</Body></root>"
        );
    }

    #[test]
    fn test_extract_preserves_parent_namespaces() {
        let xml = r#"<?xml version="1.0"?>
            <soapenv:Envelope xmlns:soapenv="http://soapenv.com" xmlns:wsse="http://wsse.com" xmlns:wsu="http://wsu.com">
                <soapenv:Header>
                    <wsse:Security>
                        <wsu:Timestamp wsu:Id="TS-1">
                            <wsu:Created>2024-01-01T00:00:00Z</wsu:Created>
                            <wsu:Expires>2024-01-01T00:05:00Z</wsu:Expires>
                        </wsu:Timestamp>
                    </wsse:Security>
                </soapenv:Header>
                <soapenv:Body>
                    <test>content</test>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        // Extract Security header - should include parent namespace declarations
        let result = extract_element(xml, "Security");
        assert!(result.is_ok());
        let security = result.unwrap();

        // Verify that parent namespaces are preserved in the extracted element
        assert!(security.contains("xmlns:soapenv=\"http://soapenv.com\""));
        assert!(security.contains("xmlns:wsse=\"http://wsse.com\""));
        assert!(security.contains("xmlns:wsu=\"http://wsu.com\""));
        assert!(security.contains("Security"));
        assert!(security.contains("Timestamp"));
    }

    #[test]
    fn test_extract_by_id_preserves_parent_namespaces() {
        let xml = r#"<?xml version="1.0"?>
            <soapenv:Envelope xmlns:soapenv="http://soapenv.com" xmlns:wsu="http://wsu.com">
                <soapenv:Body wsu:Id="body-123">
                    <test>content</test>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        // Extract element by ID - should include parent namespace declarations
        let result = extract_element_by_id(xml, "body-123");
        assert!(result.is_ok());
        let body = result.unwrap();

        // Verify that parent namespaces are preserved
        assert!(body.contains("xmlns:soapenv=\"http://soapenv.com\""));
        assert!(body.contains("xmlns:wsu=\"http://wsu.com\""));
        assert!(body.contains("wsu:Id=\"body-123\""));
    }

    #[test]
    fn test_multiple_depth_extraction_preserves_namespaces() {
        let xml = r#"<?xml version="1.0"?>
            <soapenv:Envelope xmlns:soapenv="http://soapenv.com" xmlns:eid="http://eid.com" xmlns:wsu="http://wsu.com">
                <soapenv:Body wsu:Id="Body-123">
                    <eid:getServerInfoRequest/>
                </soapenv:Body>
            </soapenv:Envelope>"#;

        // First extraction: extract the Body element
        let body_result = extract_element_by_id(xml, "Body-123");
        assert!(body_result.is_ok());
        let body_xml = body_result.unwrap();

        // Verify parent namespaces are preserved in first extraction
        assert!(body_xml.contains("xmlns:soapenv=\"http://soapenv.com\""));
        assert!(body_xml.contains("xmlns:wsu=\"http://wsu.com\""));
        assert!(body_xml.contains("xmlns:eid=\"http://eid.com\""));

        // Second extraction: extract from the already extracted Body element
        let request_result = extract_element(&body_xml, "getServerInfoRequest");
        assert!(request_result.is_ok());
        let request_xml = request_result.unwrap();

        // Verify that namespaces from the original XML are preserved
        assert!(request_xml.contains("getServerInfoRequest"));
        assert!(request_xml.contains("xmlns:soapenv=\"http://soapenv.com\""));
        assert!(request_xml.contains("xmlns:wsu=\"http://wsu.com\""));
        assert!(request_xml.contains("xmlns:eid=\"http://eid.com\""));
    }

    #[test]
    fn test_extract_element_avoids_namespace_duplicates() {
        let xml = r#"<?xml version="1.0"?>
            <soapenv:Envelope xmlns:soapenv="http://soapenv.com" xmlns:wsse="http://wsse.com">
                <soapenv:Header>
                    <wsse:Security xmlns:wsse="http://wsse.com">
                        <test>content</test>
                    </wsse:Security>
                </soapenv:Header>
            </soapenv:Envelope>"#;

        // Extract Security header - should not duplicate the wsse namespace
        let result = extract_element(xml, "Security");
        assert!(result.is_ok());
        let security = result.unwrap();

        // Count occurrences of wsse namespace declaration
        let wsse_ns_count = security.matches("xmlns:wsse=\"http://wsse.com\"").count();
        assert_eq!(wsse_ns_count, 1);

        // Verify soapenv namespace from parent is preserved
        assert!(security.contains("xmlns:soapenv=\"http://soapenv.com\""));
    }
}
