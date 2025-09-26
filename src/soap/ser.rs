use std::io::Cursor;

use crate::soap::config::XmlConfig;
use quick_xml::events::{BytesDecl, Event};
use quick_xml::se::to_writer as quick_xml_to_writer;
use quick_xml::{Reader, SeError, Writer};
use serde::Serialize;

const XML_VERSION: &str = "1.0";

/// Serializes a value to an XML string with the given configuration
pub fn to_string<T>(config: &XmlConfig, value: &T) -> Result<String, SeError>
where
    T: Serialize,
{
    let mut xml_buf = String::new();
    quick_xml_to_writer(&mut xml_buf, value)?;

    let mut reader = Reader::from_reader(Cursor::new(xml_buf.as_bytes()));
    reader.config_mut().trim_text(true);

    let mut output_buf = Vec::with_capacity(xml_buf.len());
    let mut writer = if config.pretty {
        Writer::new_with_indent(&mut output_buf, config.indent.0 as u8, config.indent.1)
    } else {
        Writer::new(&mut output_buf)
    };

    if config.xml_decl {
        let decl = BytesDecl::new(XML_VERSION, Some(&config.encoding), None);
        writer.write_event(Event::Decl(decl))?;
    }

    let mut buf = Vec::new();
    let mut is_root = true;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let mut start = e.into_owned();
                if is_root {
                    for (prefix, uri) in config.namespaces.iter() {
                        let attr_name = if prefix.is_empty() {
                            "xmlns".into()
                        } else {
                            format!("xmlns:{prefix}")
                        };
                        start.push_attribute((attr_name.as_bytes(), uri.as_bytes()));
                    }
                    is_root = false;
                }
                writer.write_event(Event::Start(start))?;
            }
            Ok(Event::Eof) => break,
            Ok(event) => writer.write_event(event)?,
            Err(e) => return Err(SeError::Custom(e.to_string())),
        }
        buf.clear();
    }

    std::str::from_utf8(&output_buf)
        .map(|s| s.to_string())
        .map_err(Into::into)
}

#[macro_export]
macro_rules! impl_serialize {
    ($name:ident, $prefix:literal) => {
        impl<T> Serialize for $name<'_, T>
        where
            T: Serialize,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeStruct;

                const ENVELOPE_NAME: &'static str = concat!($prefix, ":Envelope");
                const HEADER_NAME: &'static str = concat!($prefix, ":Header");
                const BODY_NAME: &'static str = concat!($prefix, ":Body");

                let envelope = self.0;
                let field_count = if envelope.header.is_some() { 2 } else { 1 };
                let mut state = serializer.serialize_struct(ENVELOPE_NAME, field_count)?;

                if let Some(header) = envelope.header() {
                    state.serialize_field(HEADER_NAME, header)?;
                }
                state.serialize_field(BODY_NAME, envelope.body())?;
                state.end()
            }
        }
    };
}
