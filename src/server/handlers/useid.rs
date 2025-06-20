use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use flate2::bufread::DeflateDecoder;
use quick_xml::{
    escape::escape, events::{BytesCData, BytesDecl, BytesEnd, BytesStart, BytesText, Event}, name::{Namespace, ResolveResult}, NsReader, Writer
};
use serde::Deserialize;
use std::io::{Cursor, Read};
use tracing::{debug, error, info, warn};

use crate::{
    domain::eid::ports::{EIDService, EidService},
    eid::{
        common::models::{AttributeRequester, LevelOfAssurance, OperationsRequester},
        use_id::{
            model::{
                AgeVerificationRequest, PlaceVerificationRequest, UseIDRequest, UseIDResponse,
            },
            parser::parse_use_id_request,
        },
    },
    server::AppState,
};

/// SAML query parameters for HTTP-Redirect binding
#[derive(Deserialize)]
pub struct SamlQueryParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
    #[serde(rename = "SigAlg")]
    sig_alg: Option<String>,
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

/// Handles incoming useID requests, supporting both SAML HTTP-Redirect (GET) and SOAP (POST) bindings.
/// For SAML requests, decodes and parses the SAMLRequest query parameter into a UseIDRequest.
/// For SOAP requests, parses the request body as SOAP XML.
/// Processes the request using the EIDService and returns a SOAP response.
pub async fn use_id_handler<S: EIDService + EidService>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Query(query): Query<SamlQueryParams>,
    body: String,
) -> impl IntoResponse {
    info!("=== useID Handler Called ===");

    // Handle GET request with SAMLRequest query parameter
    if let Some(saml_request) = query.saml_request {
        info!("Processing SAML HTTP-Redirect request");

        // Decode URL-encoded SAMLRequest
        let decoded_saml = match urlencoding::decode(&saml_request) {
            Ok(decoded) => decoded.into_owned(),
            Err(err) => {
                error!("Failed to URL-decode SAMLRequest: {}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    "Failed to decode SAMLRequest".to_string(),
                )
                    .into_response();
            }
        };

        // Decode base64-encoded SAMLRequest
        let saml_bytes = match base64::engine::general_purpose::STANDARD.decode(&decoded_saml) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!("Failed to base64-decode SAMLRequest: {}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    "Failed to decode SAMLRequest".to_string(),
                )
                    .into_response();
            }
        };

        // Decompress DEFLATE-encoded SAMLRequest
        let mut decoder = DeflateDecoder::new(&saml_bytes[..]);
        let mut saml_xml = String::new();
        if let Err(err) = decoder.read_to_string(&mut saml_xml) {
            error!("Failed to decompress SAMLRequest: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                "Failed to decompress SAMLRequest".to_string(),
            )
                .into_response();
        }

        info!(
            "SAMLRequest XML (length: {}): {}",
            saml_xml.len(),
            saml_xml.chars().take(200).collect::<String>()
        );
        debug!("Full SAMLRequest XML: {}", saml_xml);

        // Parse SAML XML into UseIDRequest
        let use_id_request = match parse_saml_to_use_id_request(&saml_xml) {
            Ok(request) => {
                info!("SAML request parsed successfully");
                debug!("Parsed UseIDRequest: {:?}", request);
                request
            }
            Err(err) => {
                error!("Failed to parse SAML request: {}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to parse SAML request: {err}"),
                )
                    .into_response();
            }
        };

        // Process the request
        let response = match state.use_id.handle_use_id(use_id_request) {
            Ok(response) => {
                info!("useID request processed successfully");
                debug!("Response: {:?}", response);
                // Add detailed logging
                debug!(
                    "Response details: session_id={}, psk_id={}, psk_key={}, ecard_server_address={:?}",
                    response.session.id,
                    response.psk.id,
                    response.psk.key,
                    response.ecard_server_address
                );
                response
            }
            Err(err) => {
                error!("Error processing useID request: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response();
            }
        };

        // Serialize to SOAP response
        match build_use_id_response_local(&response) {
            Ok(soap_response) => {
                info!("SOAP response: {}", soap_response);
                info!(
                    "Response serialized successfully, length: {} bytes",
                    soap_response.len()
                );
                (
                    StatusCode::OK,
                    create_soap_response_headers(),
                    soap_response,
                )
                    .into_response()
            }
            Err(err) => {
                error!("Failed to serialize SOAP response: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create SOAP response".to_string(),
                )
                    .into_response()
            }
        }
    } else {
        // Handle SOAP POST requests
        info!("Processing SOAP request");
        info!("Request body length: {} bytes", body.len());
        info!(
            "Request body preview: {}",
            body.chars().take(200).collect::<String>()
        );
        info!("Headers: {:?}", headers);

        if !is_soap_content_type(&headers) {
            warn!("Invalid content type - expected SOAP XML content type");
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Expected SOAP XML content type".to_string(),
            )
                .into_response();
        }

        let use_id_request = match parse_use_id_request(&body) {
            Ok(request) => {
                info!("SOAP request parsed: {:?}", request);
                request
            }
            Err(err) => {
                error!("Failed to parse SOAP request: {}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to parse SOAP request: {err}"),
                )
                    .into_response();
            }
        };

        let response = match state.use_id.handle_use_id(use_id_request) {
            Ok(response) => {
                info!("useID request processed successfully");
                debug!("Response: {:?}", response);
                response
            }
            Err(err) => {
                error!("Error processing useID request: {}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response();
            }
        };

        match build_use_id_response_local(&response) {
            Ok(soap_response) => {
                info!(
                    "Response serialized successfully, length: {} bytes",
                    soap_response.len()
                );
                (
                    StatusCode::OK,
                    create_soap_response_headers(),
                    soap_response,
                )
                    .into_response()
            }
            Err(err) => {
                error!("Failed to serialize SOAP response: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create SOAP response".to_string(),
                )
                    .into_response()
            }
        }
    }
}

/// Parses a SAML AuthnRequest XML string into a UseIDRequest struct.
/// Extracts requested attributes, age verification, and place verification details
/// from the SAML request, mapping them to the appropriate UseIDRequest fields.
/// Returns an error if the XML is malformed or missing required elements.
/// Compatible with older quick_xml versions (e.g., 0.22) using NsReader.
fn parse_saml_to_use_id_request(saml_xml: &str) -> Result<UseIDRequest, String> {
    const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    const _EID_NS: &str = "http://bsi.bund.de/eID/";

    let mut reader = NsReader::from_str(saml_xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut operations = OperationsRequester {
        document_type: AttributeRequester::NOT_REQUESTED,
        issuing_state: AttributeRequester::NOT_REQUESTED,
        date_of_expiry: AttributeRequester::NOT_REQUESTED,
        given_names: AttributeRequester::NOT_REQUESTED,
        family_names: AttributeRequester::NOT_REQUESTED,
        artistic_name: AttributeRequester::NOT_REQUESTED,
        academic_title: AttributeRequester::NOT_REQUESTED,
        date_of_birth: AttributeRequester::NOT_REQUESTED,
        place_of_birth: AttributeRequester::NOT_REQUESTED,
        nationality: AttributeRequester::NOT_REQUESTED,
        birth_name: AttributeRequester::NOT_REQUESTED,
        place_of_residence: AttributeRequester::NOT_REQUESTED,
        community_id: None,
        residence_permit_id: None,
        restricted_id: AttributeRequester::NOT_REQUESTED,
        age_verification: AttributeRequester::NOT_REQUESTED,
        place_verification: AttributeRequester::NOT_REQUESTED,
    };
    let mut age_verification = AgeVerificationRequest { _age: 0 };
    let mut place_verification = PlaceVerificationRequest {
        _community_id: String::new(),
    };
    let mut level_of_assurance: Option<LevelOfAssurance> = None;
    let mut in_authn_request = false;
    let mut in_attribute = false;
    let mut current_attribute = String::new();
    let mut is_required = false; // Declare is_required at function scope
    let mut depth = 0;
    let mut root_element: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                let (ns_result, local_name) = reader.resolve_element(e.name());
                let namespace = match ns_result {
                    ResolveResult::Bound(Namespace(ns)) => {
                        std::str::from_utf8(ns).unwrap_or("unknown")
                    }
                    ResolveResult::Unbound => "unbound",
                    ResolveResult::Unknown(_) => "unknown",
                };
                let local_name_str = std::str::from_utf8(local_name.as_ref()).unwrap_or("invalid");
                debug!(
                    "Start element (depth: {}): local_name={}, namespace={}",
                    depth, local_name_str, namespace
                );

                if depth == 1 {
                    root_element = Some(local_name_str.to_string());
                    debug!("Root element: {}", local_name_str);
                }

                // Check for AuthnRequest with relaxed namespace check
                if local_name.as_ref() == b"AuthnRequest" {
                    in_authn_request = true;
                    debug!("Found AuthnRequest (namespace: {})", namespace);
                    if namespace != SAML_PROTOCOL_NS {
                        warn!("Unexpected namespace for AuthnRequest: {}", namespace);
                    }
                } else if in_authn_request
                    && namespace == SAML_ASSERTION_NS
                    && local_name.as_ref() == b"Attribute"
                {
                    in_attribute = true;
                    is_required = false; // Reset is_required for new attribute
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| format!("Invalid attribute: {}", e))?;
                        let (attr_ns_result, attr_local_name) = reader.resolve_attribute(attr.key);
                        let attr_namespace = match attr_ns_result {
                            ResolveResult::Bound(Namespace(ns)) => {
                                std::str::from_utf8(ns).unwrap_or("unknown")
                            }
                            ResolveResult::Unbound => "unbound",
                            ResolveResult::Unknown(_) => "unknown",
                        };
                        debug!(
                            "Attribute: local_name={:?}, namespace={}",
                            std::str::from_utf8(attr_local_name.as_ref()).unwrap_or("invalid"),
                            attr_namespace
                        );
                        if attr_local_name.as_ref() == b"Name" {
                            current_attribute = attr
                                .unescape_value()
                                .map_err(|e| format!("Invalid attribute name: {}", e))?
                                .into_owned();
                            debug!("Current attribute name: {}", current_attribute);
                        } else if attr_local_name.as_ref() == b"isRequired" {
                            is_required = attr
                                .unescape_value()
                                .map_err(|e| format!("Invalid isRequired value: {}", e))?
                                .to_lowercase()
                                == "true";
                            debug!("Attribute isRequired: {}", is_required);
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                depth -= 1;
                let (ns_result, local_name) = reader.resolve_element(e.name());
                let namespace = match ns_result {
                    ResolveResult::Bound(Namespace(ns)) => {
                        std::str::from_utf8(ns).unwrap_or("unknown")
                    }
                    ResolveResult::Unbound => "unbound",
                    ResolveResult::Unknown(_) => "unknown",
                };
                let local_name_str = std::str::from_utf8(local_name.as_ref()).unwrap_or("invalid");
                debug!(
                    "End element (depth: {}): local_name={}, namespace={}",
                    depth, local_name_str, namespace
                );

                if namespace == SAML_ASSERTION_NS && local_name.as_ref() == b"Attribute" {
                    in_attribute = false;
                    current_attribute.clear();
                    is_required = false; // Reset is_required when leaving attribute
                } else if local_name.as_ref() == b"AuthnRequest" {
                    in_authn_request = false;
                    debug!("Closed AuthnRequest");
                }
            }
            Ok(Event::Text(e)) if in_attribute => {
                let value = e
                    .unescape()
                    .map_err(|e| format!("Failed to unescape attribute value: {}", e))?
                    .into_owned();
                debug!("Text value for attribute {}: {}", current_attribute, value);
                let attribute_status = if is_required {
                    AttributeRequester::REQUIRED
                } else {
                    AttributeRequester::ALLOWED
                };
                match current_attribute.as_str() {
                    "documentType" => operations.document_type = attribute_status,
                    "issuingState" => operations.issuing_state = attribute_status,
                    "dateOfExpiry" => operations.date_of_expiry = attribute_status,
                    "givenNames" => operations.given_names = attribute_status,
                    "familyNames" => operations.family_names = attribute_status,
                    "artisticName" => operations.artistic_name = attribute_status,
                    "academicTitle" => operations.academic_title = attribute_status,
                    "dateOfBirth" => operations.date_of_birth = attribute_status,
                    "placeOfBirth" => operations.place_of_birth = attribute_status,
                    "nationality" => operations.nationality = attribute_status,
                    "birthName" => operations.birth_name = attribute_status,
                    "placeOfResidence" => operations.place_of_residence = attribute_status,
                    "restrictedId" => operations.restricted_id = attribute_status,
                    "ageVerification" => {
                        operations.age_verification = attribute_status;
                        if let Ok(age) = value.parse::<u32>() {
                            match age.try_into() {
                                Ok(age_u8) => age_verification._age = age_u8,
                                Err(_) => {
                                    return Err("Age value exceeds u8 range (0-255)".to_string());
                                }
                            }
                        }
                    }
                    "placeVerification" => {
                        operations.place_verification = attribute_status;
                        place_verification._community_id = value;
                    }
                    "levelOfAssurance" => {
                        level_of_assurance = match value.as_str() {
                            "low" => Some(LevelOfAssurance::Low),
                            "substantial" => Some(LevelOfAssurance::Substantial),
                            "high" => Some(LevelOfAssurance::High),
                            _ => return Err(format!("Invalid level of assurance: {}", value)),
                        };
                    }
                    _ => debug!("Ignoring unknown attribute: {}", current_attribute),
                }
            }
            Ok(Event::Eof) => {
                debug!("Reached EOF");
                break;
            }
            Ok(event) => {
                debug!("Other event: {:?}", event);
            }
            Err(e) => {
                let pos = reader.buffer_position();
                error!("Error parsing SAML XML at position {}: {}", pos, e);
                return Err(format!("Invalid SAML XML at position {}: {}", pos, e));
            }
        }
        buf.clear();
    }

    if !in_authn_request && root_element.as_deref() != Some("AuthnRequest") {
        error!(
            "No AuthnRequest found in SAML XML. Root element: {:?}, XML preview: {}",
            root_element,
            saml_xml.chars().take(200).collect::<String>()
        );
        return Err(format!(
            "No AuthnRequest found in SAML XML. Root element: {:?}",
            root_element
        ));
    }

    // Validate required fields
    if operations.age_verification == AttributeRequester::ALLOWED && age_verification._age == 0 {
        error!("Age verification requested but no valid age provided");
        return Err("Age verification requested but no valid age provided".to_string());
    }

    if operations.place_verification == AttributeRequester::ALLOWED
        && place_verification._community_id.is_empty()
    {
        error!("Place verification requested but no community ID provided");
        return Err("Place verification requested but no community ID provided".to_string());
    }

    Ok(UseIDRequest {
        _use_operations: operations,
        _age_verification: age_verification,
        _place_verification: place_verification,
        _transaction_info: None,
        _transaction_attestation_request: None,
        _level_of_assurance: level_of_assurance,
        _eid_type_request: None,
        _psk: None,
    })
}

/// Checks if the request headers indicate a SOAP XML content type.
fn is_soap_content_type(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.contains("text/xml")
                || v.contains("application/soap+xml")
                || v.contains("application/xml")
        })
        .unwrap_or(false)
}

/// Creates headers for the SOAP response.
fn create_soap_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        "application/soap+xml; charset=utf-8".parse().unwrap(),
    );
    headers
}

/// Builds a SOAP response from a UseIDResponse struct (local implementation).
fn build_use_id_response_local(response: &UseIDResponse) -> Result<String, String> {
    debug!(
        "Building SOAP response with: session_id={}, ecard_server_address={:?}, psk_id={}, psk_key={}, result_major={}",
        response.session.id,
        response.ecard_server_address,
        response.psk.id,
        response.psk.key,
        response.result.result_major
    );

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let decl = BytesDecl::new("1.0", Some("UTF-8"), None);
    writer.write_event(Event::Decl(decl)).map_err(|e| e.to_string())?;

    let mut envelope = BytesStart::new("soapenv:Envelope");
    envelope.push_attribute(("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/"));
    envelope.push_attribute(("xmlns:eid", "http://bsi.bund.de/eID/"));
    envelope.push_attribute(("xmlns:dss", "urn:oasis:names:tc:dss:1.0:core:schema"));
    writer.write_event(Event::Start(envelope)).map_err(|e| e.to_string())?;

    writer.write_event(Event::Start(BytesStart::new("soapenv:Body"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Start(BytesStart::new("eid:useIDResponse"))).map_err(|e| e.to_string())?;

    // CommunicationErrorAddress (use CDATA)
    writer.write_event(Event::Start(BytesStart::new("eid:CommunicationErrorAddress"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::CData(BytesCData::new("https://localhost:3000/error"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:CommunicationErrorAddress"))).map_err(|e| e.to_string())?;

    // Session
    writer.write_event(Event::Start(BytesStart::new("eid:Session"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Start(BytesStart::new("eid:ID"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Text(BytesText::from_escaped(&response.session.id))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:Session"))).map_err(|e| e.to_string())?;

    // eCardServerAddress (use escaped text)
    let ecard_url = response.ecard_server_address.as_ref().ok_or_else(|| {
        error!("eCard server address not provided in response");
        "eCard server address not provided".to_string()
    })?;
    writer.write_event(Event::Start(BytesStart::new("eid:eCardServerAddress"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Text(BytesText::from_escaped(escape(ecard_url)))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:eCardServerAddress"))).map_err(|e| e.to_string())?;

    // RefreshAddress (use CDATA)
    writer.write_event(Event::Start(BytesStart::new("eid:RefreshAddress"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::CData(BytesCData::new("https://localhost:3000/refresh"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:RefreshAddress"))).map_err(|e| e.to_string())?;

    // PSK
    writer.write_event(Event::Start(BytesStart::new("eid:PSK"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Start(BytesStart::new("eid:ID"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Text(BytesText::from_escaped(&response.psk.id))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:ID"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Start(BytesStart::new("eid:Key"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Text(BytesText::from_escaped(&response.psk.key))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:Key"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("eid:PSK"))).map_err(|e| e.to_string())?;

    // Result
    writer.write_event(Event::Start(BytesStart::new("dss:Result"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Start(BytesStart::new("dss:ResultMajor"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::Text(BytesText::from_escaped(&response.result.result_major))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("dss:ResultMajor"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("dss:Result"))).map_err(|e| e.to_string())?;

    writer.write_event(Event::End(BytesEnd::new("eid:useIDResponse"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Body"))).map_err(|e| e.to_string())?;
    writer.write_event(Event::End(BytesEnd::new("soapenv:Envelope"))).map_err(|e| e.to_string())?;

    let result = writer.into_inner().into_inner();
    debug!("Raw response bytes (length: {}): {:?}", result.len(), result);
    let response_str = String::from_utf8(result).map_err(|e| {
        error!("Failed to convert response to UTF-8: {}", e);
        e.to_string()
    })?;
    debug!("Generated SOAP response: {}", response_str);
    Ok(response_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::eid::service::{EIDServiceConfig, UseidService};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::{io::Write, sync::Arc};

    fn create_test_state() -> AppState<UseidService> {
        let service = UseidService::new(EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
        });
        let service_arc = Arc::new(service);
        AppState {
            use_id: service_arc.clone(),
            eid_service: service_arc,
        }
    }

    #[tokio::test]
    async fn test_use_id_handler_saml_request() {
        let state = create_test_state();
        let saml_request = r#"
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="id123" Version="2.0" IssueInstant="2025-06-18T12:33:00Z">
            <saml:Issuer>https://localhost:8443/realms/master</saml:Issuer>
            <samlp:RequestedAuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard</saml:AuthnContextClassRef>
            </samlp:RequestedAuthnContext>
            <saml:AttributeStatement>
                <saml:Attribute Name="givenNames" isRequired="true"><saml:AttributeValue>ALLOWED</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="familyNames" isRequired="true"><saml:AttributeValue>ALLOWED</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="ageVerification"><saml:AttributeValue>18</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="placeVerification"><saml:AttributeValue>DE123</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="levelOfAssurance"><saml:AttributeValue>substantial</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
        </samlp:AuthnRequest>
    "#;
        let compressed_saml = {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(saml_request.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&compressed_saml);
        let encoded_saml = urlencoding::encode(&base64_encoded);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/eIDService/useID?SAMLRequest={}", encoded_saml))
            .body(Body::empty())
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams {
                saml_request: Some(encoded_saml.into_owned()),
                relay_state: None,
                sig_alg: None,
                signature: None,
            }),
            String::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok"));
        assert!(body_str.contains("<eid:ID>")); 
        assert!(body_str.contains("<eid:Key>")); 
        assert!(!body_str.contains("<eid:ID></eid:ID>")); 
        assert!(!body_str.contains("<eid:Key></eid:Key>"));
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_saml() {
        let state = create_test_state();
        let invalid_saml = "<invalid>xml</invalid>";
        let compressed_saml = {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(invalid_saml.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&compressed_saml);
        let encoded_saml = urlencoding::encode(&base64_encoded);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/eIDService/useID?SAMLRequest={}", encoded_saml))
            .body(Body::empty())
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams {
                saml_request: Some(encoded_saml.into_owned()),
                relay_state: None,
                sig_alg: None,
                signature: None,
            }),
            String::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("No AuthnRequest found"));
    }
}
