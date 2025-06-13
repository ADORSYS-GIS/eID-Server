use quick_xml::de::from_str;

use super::model::{Envelope, StartPAOS};

pub fn parse_start_paos(xml: &str) -> Result<StartPAOS, quick_xml::DeError> {
    let envelope: Envelope = from_str(xml)?;
    Ok(envelope.body.start_paos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_start_paos() {
        let xml = r#"
        <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
            <S:Body>
                <iso:StartPAOS>
                    <iso:SessionIdentifier>12345</iso:SessionIdentifier>
                    <iso:ConnectionHandle>abc</iso:ConnectionHandle>
                    <iso:ConnectionHandle>def</iso:ConnectionHandle>
                </iso:StartPAOS>
            </S:Body>
        </S:Envelope>
        "#;

        let parsed = parse_start_paos(xml).expect("Failed to parse");
        assert_eq!(parsed.session_identifier, "12345");
        assert_eq!(parsed.connection_handles, vec!["abc", "def"]);
    }
}
