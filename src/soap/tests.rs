use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    pub user: User,
    #[serde(rename = "action")]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct User {
    pub name: String,
    pub age: u8,
}

#[test]
fn test_envelope_creation() {
    let request = TestData {
        user: User {
            name: "Test User".to_string(),
            age: 30,
        },
        actions: vec!["action".to_string()],
    };

    let envelope = Envelope::new(request.clone());

    assert_eq!(envelope.body(), &request);
    assert!(envelope.header().is_none());
}

#[test]
fn test_envelope_with_header() {
    let request = TestData {
        user: User {
            name: "Test User".to_string(),
            age: 30,
        },
        actions: vec!["action".to_string()],
    };
    let header = Header::default();

    let envelope = Envelope::new(request.clone()).with_header(header);

    assert!(envelope.header.is_some());
    assert_eq!(envelope.body(), &request);
    assert!(envelope.header.is_some());
}

#[test]
fn test_serialize_soap() {
    let request = TestData {
        user: User {
            name: "Test User".to_string(),
            age: 30,
        },
        actions: vec!["action1".to_string(), "action2".to_string()],
    };
    let envelope = Envelope::new(request);

    let result = envelope.serialize_soap(false);
    assert!(result.is_ok());

    let xml = result.unwrap();
    assert!(xml.contains("<soapenv:Envelope"));
    assert!(xml.contains("<soapenv:Body>"));
    assert!(xml.contains("<user>"));
    assert!(xml.contains("<name>Test User</name>"));
    assert!(xml.contains("<age>30</age>"));
    assert!(xml.contains("<action>action1</action>"));
    assert!(xml.contains("<action>action2</action>"));
    assert!(xml.contains("</soapenv:Body>"));
    assert!(xml.contains("</soapenv:Envelope>"));
}

#[test]
fn test_envelope_deserialization() {
    // Test with different prefixes
    let test_cases = [
        // soapenv prefix
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Body>
                    <TestData>
                        <user>
                            <name>Test User</name>
                            <age>30</age>
                        </user>
                        <action>action1</action>
                        <action>action2</action>
                    </TestData>
                </soapenv:Body>
            </soapenv:Envelope>"#,
        // soap prefix
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <TestData>
                        <user>
                            <name>Test User</name>
                            <age>30</age>
                        </user>
                        <action>action1</action>
                        <action>action2</action>
                    </TestData>
                </soap:Body>
            </soap:Envelope>"#,
        // No prefix
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
                <Body>
                    <TestData>
                        <user>
                            <name>Test User</name>
                            <age>30</age>
                        </user>
                        <action>action1</action>
                        <action>action2</action>
                    </TestData>
                </Body>
            </Envelope>"#,
    ];

    for (i, xml) in test_cases.iter().enumerate() {
        let result = Envelope::<TestData>::parse(xml);
        assert!(
            result.is_ok(),
            "Failed to parse XML with case {i}: {:?}",
            result.unwrap_err()
        );

        let envelope = result.unwrap();
        assert_eq!(envelope.body().user.name, "Test User");
        assert_eq!(envelope.body().user.age, 30);
        assert_eq!(
            envelope.body().actions,
            vec!["action1".to_string(), "action2".to_string()]
        );
    }
}

#[test]
fn test_invalid_field_names_rejected() {
    let invalid_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:InvalidBody>
                <message>Should fail</message>
            </soapenv:InvalidBody>
        </soapenv:Envelope>"#;

    // Should reject XML with invalid field names (InvalidBody)
    let result = Envelope::<TestData>::parse(invalid_xml);
    assert!(result.is_err());
}

#[test]
fn test_missing_body_fails() {
    let xml_without_body = r#"<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Header></soap:Header>
        </soap:Envelope>"#;

    let result = Envelope::<TestData>::parse(xml_without_body);
    // Should reject XML with missing body
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("missing field `Body`")
    );
}

#[test]
fn test_duplicate_body_fields_rejected() {
    let xml_with_duplicate = r#"<?xml version="1.0" encoding="UTF-8"?>
        <env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
            <env:Body>
                <TestData>
                    <user>
                        <name>Test User</name>
                        <age>30</age>
                    </user>
                    <action>action1</action>
                    <action>action2</action>
                </TestData>
            </env:Body>
            <env:Body>
                <TestData>
                    <user>
                        <name>Test User</name>
                        <age>30</age>
                    </user>
                    <action>action1</action>
                    <action>action2</action>
                </TestData>
            </env:Body>
        </env:Envelope>"#;

    let result = Envelope::<TestData>::parse(xml_with_duplicate);
    // Should reject XML with duplicate fields
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("duplicate field `Body`")
    );
}
