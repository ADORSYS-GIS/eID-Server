use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use flate2::bufread::DeflateDecoder;
use quick_xml::{
    NsReader,
    events::Event,
    name::{Namespace, ResolveResult},
    se::to_string,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use tracing::{debug, error, info, warn};

use crate::{
    adapters::xml_signature::{ValidationResult, XmlSignatureSigner, XmlSignatureValidator},
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

// Constants for SOAP fault responses
const SOAP_NAMESPACE: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP_SERVER_FAULT_CODE: &str = "soap:Server";
const INTERNAL_ERROR_FAULT_STRING: &str = "Internal Error";
const BSI_INTERNAL_ERROR_CODE: &str =
    "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error/common#internalError";

// SOAP fault response structs for serialization
#[derive(Debug, Serialize)]
#[serde(rename = "soap:Envelope")]
struct SoapFaultEnvelope {
    #[serde(rename = "@xmlns:soap")]
    soap: &'static str,
    #[serde(rename = "soap:Body")]
    body: SoapFaultBody,
}

#[derive(Debug, Serialize)]
struct SoapFaultBody {
    #[serde(rename = "soap:Fault")]
    fault: SoapFault,
}

#[derive(Debug, Serialize)]
struct SoapFault {
    faultcode: &'static str,
    faultstring: &'static str,
    detail: SoapFaultDetail,
}

#[derive(Debug, Serialize)]
struct SoapFaultDetail {
    #[serde(rename = "ErrorCode")]
    error_code: &'static str,
}

// Centralized XML signature configuration

/// Configuration for XML signature certificate and key file paths
#[derive(Debug, Clone)]
pub struct XmlSignatureConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for XmlSignatureConfig {
    fn default() -> Self {
        Self {
            cert_path: get_xml_signature_cert_path(),
            key_path: get_xml_signature_key_path(),
        }
    }
}

// Backward compatibility functions
fn get_xml_signature_cert_path() -> String {
    std::env::var("XML_SIGNATURE_CERT_PATH").unwrap_or_else(|_| "Config/cert.pem".to_string())
}

fn get_xml_signature_key_path() -> String {
    std::env::var("XML_SIGNATURE_KEY_PATH").unwrap_or_else(|_| "Config/key.pem".to_string())
}

// TCTokenType structs for serialization
#[derive(Debug, Serialize)]
#[serde(rename = "TCTokenType")]
struct TCTokenType {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "ServerAddress")]
    server_address: String,
    #[serde(rename = "SessionIdentifier")]
    session_identifier: String,
    #[serde(rename = "RefreshAddress")]
    refresh_address: &'static str,
    #[serde(rename = "Binding")]
    binding: &'static str,
    #[serde(rename = "PathSecurity-Protocol")]
    path_security_protocol: &'static str,
    #[serde(rename = "PathSecurity-Parameters")]
    path_security_parameters: PathSecurityParameters,
}

#[derive(Debug, Serialize)]
struct PathSecurityParameters {
    #[serde(rename = "PSK")]
    psk: String,
}

// SOAP response structs for serialization
#[derive(Debug, Serialize)]
#[serde(rename = "Envelope", rename_all = "camelCase")]
struct SoapEnvelope {
    #[serde(rename = "xmlns:soapenv")]
    soapenv: &'static str,
    #[serde(rename = "xmlns:eid")]
    eid: &'static str,
    #[serde(rename = "xmlns:dss")]
    dss: &'static str,
    body: SoapBody,
}

#[derive(Debug, Serialize)]
struct SoapBody {
    #[serde(rename = "useIDResponse")]
    use_id_response: UseIDResponseXml,
}

#[derive(Debug, Serialize)]
struct UseIDResponseXml {
    #[serde(rename = "CommunicationErrorAddress")]
    communication_error_address: &'static str,
    #[serde(rename = "RefreshAddress")]
    refresh_address: &'static str,
    #[serde(rename = "eCardServerAddress")]
    ecard_server_address: String,
    #[serde(rename = "Session")]
    session: SessionXml,
    #[serde(rename = "PSK")]
    psk: PskXml,
    #[serde(rename = "Result")]
    result: ResultXml,
}

#[derive(Debug, Serialize)]
struct SessionXml {
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Debug, Serialize)]
struct PskXml {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Debug, Serialize)]
struct ResultXml {
    #[serde(rename = "ResultMajor")]
    result_major: String,
}

/// SAML query parameters for HTTP-Redirect binding
#[derive(Debug, Deserialize)]
pub struct SamlQueryParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
}

/// Handles incoming useID requests, supporting both SAML HTTP-Redirect (GET) and SOAP (POST) bindings.
/// For SAML requests, decodes and parses the SAMLRequest query parameter into a UseIDRequest.
/// For SOAP requests, parses the request body as SOAP XML.
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
        let response = match state.use_id.handle_use_id(use_id_request).await {
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

        // For SAML binding, return TCToken XML instead of SOAP
        match build_tc_token(&response) {
            Ok(tc_token) => {
                info!("TCToken XML: {}", tc_token);
                info!(
                    "TCToken serialized successfully, length: {} bytes",
                    tc_token.len()
                );
                (StatusCode::OK, create_xml_response_headers(), tc_token).into_response()
            }
            Err(err) => {
                error!("Failed to serialize TCToken: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create TCToken".to_string(),
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

        // First, try to parse the SOAP request to ensure it's valid XML
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

        // Validate XML signature (InitiatorToken) as per requirements
        let validator = match create_xml_signature_validator() {
            Ok(validator) => validator,
            Err(e) => {
                error!("Failed to create XML signature validator: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response();
            }
        };

        match validator.validate_soap_signature(&body) {
            ValidationResult::Valid => {
                info!(
                    "XML signature validation successful - message_size: {} bytes, contains_signature: true",
                    body.len()
                );
            }
            ValidationResult::Invalid(reason) => {
                error!("XML signature validation failed: {}", reason);
                return (StatusCode::BAD_REQUEST, create_internal_error_response()).into_response();
            }
            ValidationResult::MissingSignature => {
                error!("Missing XML signature in SOAP request");
                return (StatusCode::BAD_REQUEST, create_internal_error_response()).into_response();
            }
            ValidationResult::CertificateError(reason) => {
                error!("Certificate validation failed: {}", reason);
                return (StatusCode::BAD_REQUEST, create_internal_error_response()).into_response();
            }
        }

        let response = match state.use_id.handle_use_id(use_id_request).await {
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

                // Sign SOAP response (RecipientToken) as per requirements
                // BSI requirement: eID-Server MUST apply XML digital signature - no fallback to unsigned responses
                let signed_response = match create_xml_signature_signer() {
                    Ok(signer) => {
                        match signer.sign_soap_response(&soap_response) {
                            Ok(signed) => {
                                info!(
                                    "SOAP response signed successfully - original_size: {} bytes, signed_size: {} bytes",
                                    soap_response.len(),
                                    signed.len()
                                );
                                signed
                            }
                            Err(e) => {
                                error!("Failed to sign SOAP response: {}", e);
                                // BSI compliance: Return internalError instead of unsigned response
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    create_internal_error_response(),
                                )
                                    .into_response();
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to create XML signature signer: {}", e);
                        // BSI compliance: Return internalError instead of unsigned response
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            create_internal_error_response(),
                        )
                            .into_response();
                    }
                };

                (
                    StatusCode::OK,
                    create_soap_response_headers(),
                    signed_response,
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

/// Builds TCTokenType XML from UseIDResponse using serde
pub fn build_tc_token(response: &UseIDResponse) -> Result<String, String> {
    // Validate PSK format
    if response.psk.key.len() != 64 || hex::decode(&response.psk.key).is_err() {
        return Err("Invalid PSK format in response".to_string());
    }

    let server_address = response
        .ecard_server_address
        .as_ref()
        .and_then(|url| url.split('?').next())
        .ok_or("No ecard_server_address")?;

    let tc_token = TCTokenType {
        xmlns: "http://www.bsi.bund.de/ecard/api/1.1",
        server_address: server_address.to_string(),
        session_identifier: response.session.id.clone(),
        refresh_address: "https://localhost:3000/refresh",
        binding: "urn:liberty:paos:2006-08",
        path_security_protocol: "urn:ietf:rfc:4279",
        path_security_parameters: PathSecurityParameters {
            psk: response.psk.key.clone(),
        },
    };

    let xml = to_string(&tc_token).map_err(|e| {
        error!("Failed to serialize TCToken: {}", e);
        e.to_string()
    })?;

    // Prepend XML declaration since serde_xml_rs doesn't include it
    let xml_with_decl = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{xml}");
    Ok(xml_with_decl)
}

/// Creates headers for XML response
fn create_xml_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        "application/xml; charset=utf-8".parse().unwrap(),
    );
    headers
}

/// Parses a SAML AuthnRequest XML string into a UseIDRequest struct.
fn parse_saml_to_use_id_request(saml_xml: &str) -> Result<UseIDRequest, String> {
    const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    const _EID_NS: &str = "http://bsi.bund.de/eID/";

    let mut reader = NsReader::from_str(saml_xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut operations = OperationsRequester {
        document_type: AttributeRequester::NotRequested,
        issuing_state: AttributeRequester::NotRequested,
        date_of_expiry: AttributeRequester::NotRequested,
        given_names: AttributeRequester::NotRequested,
        family_names: AttributeRequester::NotRequested,
        artistic_name: AttributeRequester::NotRequested,
        academic_title: AttributeRequester::NotRequested,
        date_of_birth: AttributeRequester::NotRequested,
        place_of_birth: AttributeRequester::NotRequested,
        nationality: AttributeRequester::NotRequested,
        birth_name: AttributeRequester::NotRequested,
        place_of_residence: AttributeRequester::NotRequested,
        community_id: None,
        residence_permit_id: None,
        restricted_id: AttributeRequester::NotRequested,
        age_verification: AttributeRequester::NotRequested,
        place_verification: AttributeRequester::NotRequested,
    };
    let mut age_verification = AgeVerificationRequest { _age: 0 };
    let mut place_verification = PlaceVerificationRequest {
        _community_id: String::new(),
    };
    let mut level_of_assurance: Option<LevelOfAssurance> = None;
    let mut in_authn_request = false;
    let mut in_attribute = false;
    let mut current_attribute = String::new();
    let mut is_required = false;
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
                    is_required = false;
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| format!("Invalid attribute: {e}"))?;
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
                                .map_err(|e| format!("Invalid attribute name: {e}"))?
                                .into_owned();
                            debug!("Current attribute name: {}", current_attribute);
                        } else if attr_local_name.as_ref() == b"isRequired" {
                            is_required = attr
                                .unescape_value()
                                .map_err(|e| format!("Invalid isRequired value: {e}"))?
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
                    is_required = false;
                } else if local_name.as_ref() == b"AuthnRequest" {
                    in_authn_request = false;
                    debug!("Closed AuthnRequest");
                }
            }
            Ok(Event::Text(e)) if in_attribute => {
                let value = e
                    .unescape()
                    .map_err(|e| format!("Failed to unescape attribute value: {e}"))?
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
                        if value.is_empty() {
                            return Err(
                                "Age verification requested but no valid age provided".to_string()
                            );
                        }
                        if let Ok(age) = value.parse::<u32>() {
                            match age.try_into() {
                                Ok(age_u8) => age_verification._age = age_u8,
                                Err(_) => {
                                    return Err("Age value exceeds u8 range (0-255)".to_string());
                                }
                            }
                        } else {
                            return Err("Invalid age value provided".to_string());
                        }
                    }
                    "placeVerification" => {
                        operations.place_verification = attribute_status;
                        if value.is_empty() {
                            return Err(
                                "Place verification requested but no community ID provided"
                                    .to_string(),
                            );
                        }
                        place_verification._community_id = value;
                    }
                    "levelOfAssurance" => {
                        level_of_assurance = match value.as_str() {
                            "low" => Some(LevelOfAssurance::Low),
                            "substantial" => Some(LevelOfAssurance::Substantial),
                            "high" => Some(LevelOfAssurance::High),
                            _ => return Err(format!("Invalid level of assurance: {value}")),
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
                error!("Error parsing SAML XML at position {pos}: {e}");
                return Err(format!("Invalid SAML XML at position {pos}: {e}"));
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
            "No AuthnRequest found in SAML XML. Root element: {root_element:?}",
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

/// Creates an XML signature validator with trusted certificates using configuration
fn create_xml_signature_validator_with_config(
    config: &XmlSignatureConfig,
) -> Result<XmlSignatureValidator, String> {
    let mut validator = XmlSignatureValidator::new()?;

    // Add trusted certificates from configuration
    if std::path::Path::new(&config.cert_path).exists() {
        validator.add_trusted_cert_from_file(&config.cert_path)?;
    } else {
        // For development/testing, we can continue without trusted certificates
        // In production, this should be a hard error
        warn!("Trusted certificate file not found: {}", config.cert_path);
    }

    Ok(validator)
}

/// Creates an XML signature validator with trusted certificates (backward compatibility)
fn create_xml_signature_validator() -> Result<XmlSignatureValidator, String> {
    let config = XmlSignatureConfig::default();
    create_xml_signature_validator_with_config(&config)
}

/// Creates an internal error response as per requirements
/// Returns a proper SOAP fault with the error code .../common#internalError
fn create_internal_error_response() -> String {
    // As per BSI requirements, respond with error code .../common#internalError
    let soap_fault_envelope = SoapFaultEnvelope {
        soap: SOAP_NAMESPACE,
        body: SoapFaultBody {
            fault: SoapFault {
                faultcode: SOAP_SERVER_FAULT_CODE,
                faultstring: INTERNAL_ERROR_FAULT_STRING,
                detail: SoapFaultDetail {
                    error_code: BSI_INTERNAL_ERROR_CODE,
                },
            },
        },
    };

    let xml = to_string(&soap_fault_envelope)
        .expect("SOAP fault serialization should never fail with valid structs");

    // Prepend XML declaration since serde_xml_rs doesn't include it
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{xml}")
}

/// Creates an XML signature signer with eID-Server certificate using configuration
fn create_xml_signature_signer_with_config(
    config: &XmlSignatureConfig,
) -> Result<XmlSignatureSigner, String> {
    XmlSignatureSigner::new_from_files(&config.key_path, &config.cert_path)
        .map_err(|e| e.to_string())
}

/// Creates an XML signature signer with eID-Server certificate (backward compatibility)
fn create_xml_signature_signer() -> Result<XmlSignatureSigner, String> {
    let config = XmlSignatureConfig::default();
    create_xml_signature_signer_with_config(&config)
}

/// Builds a SOAP response from a UseIDResponse struct using serde
fn build_use_id_response_local(response: &UseIDResponse) -> Result<String, String> {
    debug!(
        "Building SOAP response with: session_id={}, ecard_server_address={:?}, psk_id={}, psk_key={}, result_major={}",
        response.session.id,
        response.ecard_server_address,
        response.psk.id,
        response.psk.key,
        response.result.result_major
    );

    let ecard_server_address = response.ecard_server_address.as_ref().ok_or_else(|| {
        error!("eCard server address not provided in response");
        "eCard server address not provided".to_string()
    })?;

    let envelope = SoapEnvelope {
        soapenv: "http://schemas.xmlsoap.org/soap/envelope/",
        eid: "http://bsi.bund.de/eID/",
        dss: "urn:oasis:names:tc:dss:1.0:core:schema",
        body: SoapBody {
            use_id_response: UseIDResponseXml {
                communication_error_address: "https://localhost:3000/error",
                refresh_address: "https://localhost:3000/refresh",
                ecard_server_address: ecard_server_address.to_string(),
                session: SessionXml {
                    id: response.session.id.clone(),
                },
                psk: PskXml {
                    id: response.psk.id.clone(),
                    key: response.psk.key.clone(),
                },
                result: ResultXml {
                    result_major: response.result.result_major.clone(),
                },
            },
        },
    };

    let xml = to_string(&envelope).map_err(|e| {
        error!("Failed to serialize SOAP response: {}", e);
        e.to_string()
    })?;

    // Prepend XML declaration since serde_xml_rs doesn't include it
    let xml_with_decl = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{xml}");
    debug!("Generated SOAP response: {}", xml_with_decl);
    Ok(xml_with_decl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::eid::service::{EIDServiceConfig, UseidService},
        eid::{
            common::models::{ResultMajor, SessionResponse},
            use_id::model::Psk,
        },
    };
    use axum::{
        body::Body,
        http::{self, HeaderValue, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::{io::Write, sync::Arc};

    fn create_test_state() -> AppState<UseidService> {
        let service = UseidService::new(EIDServiceConfig {
            max_sessions: 10,
            session_timeout_minutes: 5,
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
            redis_url: None,
        });
        let service_arc = Arc::new(service);
        AppState {
            use_id: service_arc.clone(),
            eid_service: service_arc,
        }
    }

    fn create_saml_request(saml_xml: &str) -> String {
        let compressed_saml = {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(saml_xml.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&compressed_saml);
        urlencoding::encode(&base64_encoded).into_owned()
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
                <saml:Attribute Name="givenNames" isRequired="true"></saml:Attribute>
                <saml:Attribute Name="familyNames" isRequired="true"></saml:Attribute>
                <saml:Attribute Name="ageVerification"><saml:AttributeValue>18</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="placeVerification"><saml:AttributeValue>DE123</saml:AttributeValue></saml:Attribute>
                <saml:Attribute Name="levelOfAssurance"><saml:AttributeValue>substantial</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
        </samlp:AuthnRequest>
        "#;
        let encoded_saml = create_saml_request(saml_request);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/eIDService/useID?SAMLRequest={encoded_saml}"))
            .body(Body::empty())
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams {
                saml_request: Some(encoded_saml),
            }),
            String::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get("content-type"),
            Some(&HeaderValue::from_static("application/xml; charset=utf-8"))
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // Verify TCToken structure
        assert!(body_str.contains("<TCTokenType"));
        assert!(
            body_str.contains("<ServerAddress>https://test.eid.example.com/ecard</ServerAddress>")
        );
        assert!(body_str.contains("<SessionIdentifier>"));
        assert!(
            body_str.contains("<RefreshAddress>https://localhost:3000/refresh</RefreshAddress>")
        );
        assert!(body_str.contains("<Binding>urn:liberty:paos:2006-08</Binding>"));
        assert!(
            body_str.contains("<PathSecurity-Protocol>urn:ietf:rfc:4279</PathSecurity-Protocol>")
        );
        assert!(body_str.contains("<PathSecurity-Parameters>"));
        assert!(body_str.contains("<PSK>"));

        // Verify PSK is valid hexBinary (64 characters, 0-9 and a-f)
        let psk_start = body_str.find("<PSK>").unwrap() + 5;
        let psk_end = body_str.find("</PSK>").unwrap();
        let psk = &body_str[psk_start..psk_end];
        assert_eq!(psk.len(), 64, "PSK must be 64 characters long");
        assert!(
            psk.chars().all(|c| c.is_ascii_hexdigit()),
            "PSK must be valid hexadecimal"
        );

        // Verify session ID is 32 characters long (UUID v4 without hyphens)
        let session_id_start = body_str.find("<SessionIdentifier>").unwrap() + 19;
        let session_id_end = body_str.find("</SessionIdentifier>").unwrap();
        let session_id = &body_str[session_id_start..session_id_end];
        assert_eq!(
            session_id.len(),
            32,
            "Session ID must be 32 characters long"
        );
        assert!(
            session_id.chars().all(|c| c.is_ascii_hexdigit()),
            "Session ID must be valid hexadecimal"
        );
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_saml() {
        let state = create_test_state();
        let invalid_saml = "<invalid>xml</invalid>";
        let encoded_saml = create_saml_request(invalid_saml);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/eIDService/useID?SAMLRequest={encoded_saml}"))
            .body(Body::empty())
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams {
                saml_request: Some(encoded_saml),
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

    #[tokio::test]
    async fn test_use_id_handler_missing_saml_request() {
        let state = create_test_state();
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/eIDService/useID")
            .body(Body::empty())
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams { saml_request: None }),
            String::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Expected SOAP XML content type"));
    }

    #[tokio::test]
    async fn test_use_id_handler_invalid_soap_content_type() {
        let state = create_test_state();
        let soap_request = r#"
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eid="http://bsi.bund.de/eID/">
            <soapenv:Body>
                <eid:useIDRequest>
                    <eid:useOperations>
                        <eid:givenNames>REQUIRED</eid:givenNames>
                    </eid:useOperations>
                </eid:useIDRequest> 
            </soapenv:Body>
        </soapenv:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "text/plain")
            .body(Body::from(soap_request.to_string()))
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams { saml_request: None }),
            soap_request.to_string(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Expected SOAP XML content type"));
    }

    #[tokio::test]
    async fn test_use_id_handler_malformed_soap_request() {
        let state = create_test_state();
        let malformed_soap = "<invalid>soap</invalid>";

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/useID")
            .header("content-type", "application/soap+xml; charset=utf-8")
            .body(Body::from(malformed_soap.to_string()))
            .unwrap();

        let response = use_id_handler(
            State(state),
            request.headers().clone(),
            Query(SamlQueryParams { saml_request: None }),
            malformed_soap.to_string(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Failed to parse SOAP request"));
    }

    #[tokio::test]
    async fn test_parse_saml_to_use_id_request_invalid_attribute() {
        let saml_request = r#"
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="id123" Version="2.0" IssueInstant="2025-06-18T12:33:00Z">
            <saml:Issuer>https://localhost:8443/realms/master</saml:Issuer>
            <saml:AttributeStatement>
                <saml:Attribute Name="levelOfAssurance"><saml:AttributeValue>invalid</saml:AttributeValue></saml:Attribute>
            </saml:AttributeStatement>
        </samlp:AuthnRequest>
        "#;

        let result = parse_saml_to_use_id_request(saml_request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid level of assurance"));
    }

    #[tokio::test]
    async fn test_build_tc_token() {
        let response = UseIDResponse {
            result: ResultMajor {
                result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            },
            session: SessionResponse {
                id: "test-session-id".to_string(),
            },
            ecard_server_address: Some("https://test.eid.example.com/ecard".to_string()),
            psk: Psk {
                id: "test-session-id".to_string(),
                key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".to_string(),
            },
        };

        let tc_token = build_tc_token(&response).unwrap();
        println!("Generated TCToken XML: {tc_token}");

        assert!(
            tc_token.contains("<TCTokenType xmlns=\"http://www.bsi.bund.de/ecard/api/1.1\">"),
            "Expected TCTokenType with namespace, got: {tc_token}"
        );
        assert!(
            tc_token.contains("<ServerAddress>https://test.eid.example.com/ecard</ServerAddress>")
        );
        assert!(tc_token.contains("<SessionIdentifier>test-session-id</SessionIdentifier>"));
        assert!(
            tc_token.contains("<RefreshAddress>https://localhost:3000/refresh</RefreshAddress>")
        );
        assert!(tc_token.contains("<Binding>urn:liberty:paos:2006-08</Binding>"));
        assert!(
            tc_token.contains("<PathSecurity-Protocol>urn:ietf:rfc:4279</PathSecurity-Protocol>")
        );
        assert!(tc_token.contains(
            "<PSK>a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2</PSK>"
        ));
    }

    #[tokio::test]
    async fn test_build_tc_token_missing_ecard_address() {
        let response = UseIDResponse {
            result: ResultMajor {
                result_major: "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".to_string(),
            },
            session: SessionResponse {
                id: "test-session-id".to_string(),
            },
            ecard_server_address: None,
            psk: Psk {
                id: "test-session-id".to_string(),
                key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".to_string(),
            },
        };

        let result = build_tc_token(&response);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No ecard_server_address");
    }

    #[test]
    fn test_create_internal_error_response() {
        let response = create_internal_error_response();

        // Verify the response contains the expected XML structure
        assert!(response.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(response.contains("xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""));
        assert!(response.contains("soap:Server"));
        assert!(response.contains("Internal Error"));
        assert!(response.contains(
            "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error/common#internalError"
        ));

        // Verify it's valid XML by attempting to parse it
        let mut reader = quick_xml::Reader::from_str(&response);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();

        // Should be able to parse without errors
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => panic!("XML parsing failed: {e}"),
            }
            buf.clear();
        }
    }

    #[tokio::test]
    async fn test_session_id_uniqueness() {
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
            <saml:Attribute Name="givenNames" isRequired="true"></saml:Attribute>
        </saml:AttributeStatement>
    </samlp:AuthnRequest>
    "#;
        let encoded_saml = create_saml_request(saml_request);

        // Generate multiple sessions and collect session IDs
        let mut session_ids = std::collections::HashSet::new();
        for _ in 0..10 {
            // Clean up expired sessions before each request
            state
                .use_id
                .session_manager
                .remove_expired_sessions()
                .await
                .unwrap();

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(format!("/eIDService/useID?SAMLRequest={encoded_saml}"))
                .body(Body::empty())
                .unwrap();

            let response = use_id_handler(
                State(state.clone()),
                request.headers().clone(),
                Query(SamlQueryParams {
                    saml_request: Some(encoded_saml.clone()),
                }),
                String::new(),
            )
            .await
            .into_response();

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Expected OK status, got {}",
                response.status()
            );
            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

            let session_id_start = body_str.find("<SessionIdentifier>").unwrap() + 19;
            let session_id_end = body_str.find("</SessionIdentifier>").unwrap();
            let session_id = &body_str[session_id_start..session_id_end];

            assert_eq!(
                session_id.len(),
                32,
                "Session ID must be 32 characters long"
            );
            assert!(
                session_id.chars().all(|c| c.is_ascii_hexdigit()),
                "Session ID must be valid hexadecimal"
            );
            assert!(
                session_ids.insert(session_id.to_string()),
                "Duplicate session ID detected: {session_id}"
            );
        }
    }
}
