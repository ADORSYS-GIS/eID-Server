use quick_xml::de::from_str as quick_xml_from_str;
use quick_xml::events::Event;
use quick_xml::{DeError, Reader, Writer};
use serde::Deserialize;

/// Deserialize an instance of type T from a string of XML text.
pub fn from_str<T>(xml: &str) -> Result<T, DeError>
where
    T: for<'de> Deserialize<'de>,
{
    if !xml.contains('\n') && !xml.contains('\r') {
        return quick_xml_from_str(xml);
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut output_buf = Vec::with_capacity(xml.len());
    let mut writer = Writer::new(&mut output_buf);

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Text(e) => {
                let mut text = e.into_owned();
                text.inplace_trim_start();
                let empty = text.inplace_trim_end();
                if !empty {
                    writer
                        .write_event(Event::Text(text))
                        .map_err(|e| DeError::Custom(e.to_string()))?;
                }
            }
            Event::Eof => break,
            event => writer
                .write_event(event)
                .map_err(|e| DeError::Custom(e.to_string()))?,
        }
        buf.clear();
    }

    let normalized_xml =
        std::str::from_utf8(&output_buf).map_err(|e| DeError::Custom(e.to_string()))?;

    quick_xml_from_str(normalized_xml)
}
