use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::str;

use crate::soap::wsse::{Error, Result};

/// Perform Exclusive XML Canonicalization with optional inclusive namespaces
pub fn canonicalize(xml: impl AsRef<str>, inclusive_ns: Option<&[&str]>) -> Result<String> {
    let mut reader = Reader::from_str(xml.as_ref());
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = true;

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();

    // Stack of declared namespace maps
    let mut ns_declared_stack = vec![BTreeMap::new()];
    // Stack of rendered namespace maps
    let mut ns_rendered_stack = vec![BTreeMap::new()];

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                handle_start(
                    &mut writer,
                    &e,
                    &mut ns_declared_stack,
                    &mut ns_rendered_stack,
                    inclusive_ns,
                )?;
            }
            Ok(Event::End(e)) => {
                writer.write_event(Event::End(e))?;
                ns_declared_stack.pop();
                ns_rendered_stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e.xml_content().map_err(|e| Error::Xml(e.to_string()))?;
                let esc = escape_text_value(text.as_bytes())?;
                writer.write_event(Event::Text(BytesText::from_escaped(esc)))?;
            }
            Ok(Event::CData(e)) => {
                // CDATA is normalized to text content
                let v = e.into_inner();
                let normalized = normalize_line_endings(&v);
                let esc = escape_text_value(&normalized)?;
                writer.write_event(Event::Text(BytesText::from_escaped(esc)))?;
            }
            Ok(Event::GeneralRef(e)) => {
                writer.write_event(Event::GeneralRef(e))?;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(Error::Xml(e.to_string())),
        }
        buf.clear();
    }
    Ok(String::from_utf8(writer.into_inner().into_inner())?)
}

/// Normalize line endings to LF as per C14N spec
fn normalize_line_endings<'a>(text: &'a [u8]) -> Cow<'a, [u8]> {
    if !text.contains(&b'\r') {
        return Cow::Borrowed(text);
    }

    let mut result = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\r' {
            if i + 1 < text.len() && text[i + 1] == b'\n' {
                // CRLF -> LF
                result.push(b'\n');
                i += 2;
            } else {
                // CR -> LF
                result.push(b'\n');
                i += 1;
            }
        } else {
            result.push(text[i]);
            i += 1;
        }
    }
    Cow::Owned(result)
}

/// Escape attribute value per C14N rules.
fn escape_attr_value(v: &[u8]) -> Result<String> {
    let s = str::from_utf8(v)?;
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    Ok(out)
}

/// Escape text node value per C14N rules.
fn escape_text_value(v: &[u8]) -> Result<String> {
    let s = str::from_utf8(v)?;
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    Ok(out)
}

/// Handle a Start tag event: writes the start tag with canonicalized attributes & namespaces.
fn handle_start<W: std::io::Write>(
    writer: &mut Writer<W>,
    e: &BytesStart,
    ns_declared_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    ns_rendered_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    inclusive_namespaces: Option<&[&str]>,
) -> Result<()> {
    // Get parent context
    let parent_declared = ns_declared_stack.last().cloned().unwrap_or_default();
    let ns_rendered = ns_rendered_stack.last().cloned().unwrap_or_default();
    let mut current_declared = parent_declared.clone();

    // Separate namespace declarations vs regular attributes
    let mut regular_attrs = vec![];
    let mut local_ns_decls = vec![];

    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|e| Error::Xml(e.to_string()))?;
        let key = attr.key.as_ref();
        if key == b"xmlns" {
            local_ns_decls.push((vec![], attr.value.to_vec()));
        } else if key.starts_with(b"xmlns:") {
            let prefix = key[6..].to_vec();
            local_ns_decls.push((prefix, attr.value.to_vec()));
        } else {
            let unescaped_value = attr.unescape_value()?;
            regular_attrs.push((key.to_vec(), unescaped_value.into_owned().into_bytes()));
        }
    }

    // Apply namespace declarations to current declared scope
    for (prefix, uri) in &local_ns_decls {
        if uri.is_empty() {
            current_declared.remove(prefix);
        } else {
            current_declared.insert(prefix.clone(), uri.clone());
        }
    }

    // Determine visibly-utilized prefixes
    let mut visibly_utilized = BTreeSet::new();
    let name = e.name();
    let name_bytes = name.as_ref();
    if let Some(pos) = name_bytes.iter().position(|&b| b == b':') {
        let prefix = name_bytes[..pos].to_vec();
        visibly_utilized.insert(prefix.clone());
    } else {
        visibly_utilized.insert(vec![]);
    };

    for (key_bytes, _) in &regular_attrs {
        if let Some(pos) = key_bytes.iter().position(|&b| b == b':') {
            let prefix = key_bytes[..pos].to_vec();
            // xml: prefix is never rendered as it's implicitly bound
            if prefix != b"xml" {
                visibly_utilized.insert(prefix);
            }
        }
    }

    // Add inclusive namespaces to visibly utilized set
    if let Some(prefixes) = inclusive_namespaces {
        for prefix_str in prefixes {
            if current_declared.contains_key(prefix_str.as_bytes()) {
                visibly_utilized.insert(prefix_str.as_bytes().to_vec());
            }
        }
    }

    // Compute which namespace declarations to render
    let mut render_ns = Vec::new();
    for prefix in &visibly_utilized {
        if prefix == &b"xml".to_vec() {
            continue;
        }

        if let Some(current_uri) = current_declared.get(prefix) {
            // Check if this exact prefix→uri mapping has been rendered by an ancestor
            let already_rendered = ns_rendered
                .get(prefix)
                .map(|rendered_uri| rendered_uri == current_uri)
                .unwrap_or(false);

            if !already_rendered {
                render_ns.push((prefix.clone(), current_uri.clone()));
            }
        }
    }

    // Sort namespace declarations by prefix lexical order
    render_ns.sort_by(|a, b| a.0.cmp(&b.0));

    let name_str = str::from_utf8(name_bytes)?;
    let mut tag_start = format!("<{name_str}");

    // Add namespace declarations to the tag string
    for (prefix, uri) in &render_ns {
        if prefix.is_empty() {
            tag_start.push_str(" xmlns=\"");
        } else {
            let p = str::from_utf8(prefix)?;
            tag_start.push_str(&format!(" xmlns:{p}=\""));
        }
        let escaped_uri = escape_attr_value(uri)?;
        tag_start.push_str(&escaped_uri);
        tag_start.push('"');
    }

    // Sort and add regular attributes
    let mut attr_info = vec![];
    for (key_bytes, value_bytes) in &regular_attrs {
        let (ns_uri, local_name) = if let Some(pos) = key_bytes.iter().position(|&b| b == b':') {
            let prefix = &key_bytes[..pos];
            let local = key_bytes[pos + 1..].to_vec();
            let uri = if prefix == b"xml" {
                b"http://www.w3.org/XML/1998/namespace".to_vec()
            } else {
                current_declared.get(prefix).cloned().unwrap_or_default()
            };
            (uri, local)
        } else {
            (vec![], key_bytes.clone())
        };
        attr_info.push((ns_uri, local_name, key_bytes.clone(), value_bytes.clone()));
    }

    attr_info.sort_by(|a, b| match a.0.cmp(&b.0) {
        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
        other => other,
    });

    for (_, _, key_bytes, value_bytes) in &attr_info {
        let key_str = str::from_utf8(key_bytes)?;
        tag_start.push(' ');
        tag_start.push_str(key_str);
        tag_start.push_str("=\"");
        let escaped_val = escape_attr_value(value_bytes)?;
        tag_start.push_str(&escaped_val);
        tag_start.push('"');
    }

    tag_start.push('>');
    writer.get_mut().write_all(tag_start.as_bytes())?;

    // Push current declared scope
    ns_declared_stack.push(current_declared);

    // Update rendered map with what we just rendered
    let mut new_rendered = ns_rendered.clone();
    for (prefix, uri) in &render_ns {
        new_rendered.insert(prefix.clone(), uri.clone());
    }
    ns_rendered_stack.push(new_rendered);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_canonicalization() {
        let xml = r#"<root><child attr="value">text</child></root>"#;
        let result = canonicalize(xml, None).unwrap();
        assert_eq!(result, r#"<root><child attr="value">text</child></root>"#);
    }

    #[test]
    fn test_attribute_escaping() {
        let xml = r#"<root attr="&lt;&quot;&#x9;&#xA;&#xD;">text</root>"#;
        let result = canonicalize(xml, None).unwrap();
        assert!(result.contains("&lt;&quot;&#x9;&#xA;&#xD;"));
    }

    #[test]
    fn test_namespace_not_duplicated() {
        // Namespace declared on root should not be re-rendered on child
        let xml = r#"<root xmlns="http://example.com"><child>text</child></root>"#;
        let result = canonicalize(xml, None).unwrap();

        let count = result.matches(r#"xmlns="http://example.com""#).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_line_ending_normalization() {
        let input = b"hello\r\nworld\rtest";
        let result = normalize_line_endings(input);
        assert_eq!(&*result, b"hello\nworld\ntest");
    }

    #[test]
    fn test_inclusive_prefixes() {
        // With exclusive mode, 'a' namespace should not appear on child
        let xml = r#"<root xmlns:a="http://a.com"><child>text</child></root>"#;
        let result = canonicalize(xml, None).unwrap();
        let child_part = result.split("<child").nth(1).unwrap();
        assert!(!child_part.starts_with(" xmlns:a"));
    }

    #[test]
    fn test_prefix_utilized_by_element() {
        let xml = r#"<root xmlns:a="http://a.com"><a:child>text</a:child></root>"#;
        let result = canonicalize(xml, None).unwrap();
        // The 'a' prefix should be rendered on the child element because it's used
        assert!(result.contains(r#"<a:child xmlns:a="http://a.com""#));
    }

    #[test]
    fn test_prefix_utilized_by_attribute() {
        let xml = r#"<root xmlns:a="http://a.com"><child a:attr="value">text</child></root>"#;
        let result = canonicalize(xml, None).unwrap();
        // The 'a' prefix should be rendered on the child element because it's used by attribute
        assert!(result.contains(r#"<child xmlns:a="http://a.com""#));
    }

    #[test]
    fn test_inclusive_namespaces_with_prefix_list() {
        // Test case for inclusive namespaces with PrefixList
        let xml =
            r#"<root xmlns:a="http://a.com" xmlns:b="http://b.com"><child>text</child></root>"#;
        let result = canonicalize(xml, Some(&["a"])).unwrap();
        // The 'a' prefix should be rendered on the child element due to inclusive namespaces
        assert!(result.contains(r#"xmlns:a="http://a.com""#));
        // The 'b' prefix should not be rendered as it's not in the inclusive list
        assert!(!result.contains(r#"xmlns:b=""#));
    }
}
