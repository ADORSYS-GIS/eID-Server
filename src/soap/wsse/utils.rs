use crate::soap::wsse::{Error, Result};
use quick_xml::{Reader, Writer, events::Event};
use std::io::Cursor;

/// Adds a `wsu:Id` attribute to the Body element of the envelope
pub fn add_body_id_to_envelope(xml: impl AsRef<str>, body_id: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml.as_ref());
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut body_found = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(e)) => writer.write_event(Event::Decl(e))?,
            Ok(Event::Start(e)) if e.name().local_name().as_ref() == b"Body" && !body_found => {
                body_found = true;
                let mut body_elem = e.to_owned();
                if !body_elem
                    .attributes()
                    .filter_map(|a| a.ok())
                    .any(|attr| attr.key.local_name().as_ref() == b"Id")
                {
                    body_elem.push_attribute(("wsu:Id", body_id));
                }
                writer.write_event(Event::Start(body_elem.borrow()))?;
            }
            Ok(Event::Eof) => break,
            Ok(e) => writer.write_event(e)?,
            Err(e) => return Err(Error::Xml(e.to_string())),
        }
        buf.clear();
    }
    if !body_found {
        return Err(Error::Xml("No Body element found in envelope".into()));
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

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if !capturing && predicate(&e) {
                    capturing = true;
                    depth = 1;
                    writer.write_event(Event::Start(e.to_owned()))?;
                } else if capturing {
                    depth += 1;
                    writer.write_event(Event::Start(e.to_owned()))?;
                }
            }
            Ok(Event::End(e)) => {
                if capturing {
                    writer.write_event(Event::End(e.to_owned()))?;
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
        let result = add_body_id_to_envelope(xml, "body-123");
        assert!(result.is_ok());
        let envelope = result.unwrap();
        assert_eq!(
            envelope,
            "<root><Body wsu:Id=\"body-123\">content</Body></root>"
        );
    }
}
