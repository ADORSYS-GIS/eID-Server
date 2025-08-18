use crate::{
    domain::eid::{
        certificate::CertificateStore,
        models::{EAC1OutputType, EAC2OutputType, EACPhase},
        ports::{DIDAuthenticate, EIDService, EidService},
        service::DIDAuthenticateService,
        session_manager::SessionManager,
    },
    server::AppState,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use base64::Engine;
use openssl::{
    bn::BigNumContext,
    ec::{EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
};
use quick_xml::{Reader, events::Event};
use tracing::{debug, error, warn};
use uuid::Uuid;

pub const EAC_REQUIRED_CHAT: &str = "7f4c12060904007f00070301020253050000000004";
pub const EAC_OPTIONAL_CHAT: &str = "7f4c12060904007f0007030102025305000503ff00";

#[derive(Debug)]
pub enum PaosRequest {
    StartPAOS {
        session_identifier: String,
        message_id: Option<String>,
        connection_handle: ConnectionHandle,
    },

    DIDAuthenticateResponse {
        message_id: Option<String>,
        relates_to: Option<String>,
        phase: EACPhase,
        eac1_output: Box<Option<EAC1OutputType>>,
        eac2_output: Option<EAC2OutputType>,
        result_major: String,
        result_minor: Option<String>,
        result_message: Option<String>,
    },
}

#[derive(Debug)]
pub struct ConnectionHandle {
    pub card_application: String,
}

// Parser for StartPAOS
pub fn parse_start_paos(xml: &str) -> Result<PaosRequest, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut session_identifier = String::new();
    let mut message_id = None;
    let mut card_application = String::new();
    let mut in_start_paos = false;
    let mut in_connection_handle = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"StartPAOS" | b"ns4:StartPAOS" => in_start_paos = true,
                b"SessionIdentifier" | b"ns4:SessionIdentifier" if in_start_paos => {
                    session_identifier = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read SessionIdentifier: {e}"))?
                        .to_string();
                }
                b"MessageID" if in_start_paos => {
                    message_id = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read MessageID: {e}"))?
                            .to_string(),
                    );
                }
                b"ConnectionHandle" | b"ns4:ConnectionHandle" if in_start_paos => {
                    in_connection_handle = true;
                }
                b"CardApplication" | b"ns4:CardApplication" if in_connection_handle => {
                    card_application = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read CardApplication: {e}"))?
                        .to_string();
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"ConnectionHandle" | b"ns4:ConnectionHandle" => in_connection_handle = false,
                b"StartPAOS" | b"ns4:StartPAOS" => in_start_paos = false,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if card_application.is_empty() {
        return Err("Missing CardApplication in StartPAOS".to_string());
    }

    Ok(PaosRequest::StartPAOS {
        session_identifier,
        message_id,
        connection_handle: ConnectionHandle { card_application },
    })
}

// Updated parser for DIDAuthenticateResponse
pub fn parse_did_authenticate_response(xml: &str) -> Result<PaosRequest, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut message_id = None;
    let mut relates_to = None;
    let mut result_major = String::new();
    let mut result_minor = None;
    let mut result_message = None;
    let mut in_did_authenticate = false;
    let mut in_result = false;
    let mut in_auth_protocol = false;
    let mut phase = EACPhase::EAC1;
    let mut chat = String::new();
    let mut car = String::new();
    let mut ef_card_access = String::new();
    let mut id_picc = String::new();
    let mut challenge = String::new();
    let mut ef_card_security = String::new();
    let mut authentication_token = String::new();
    let mut nonce = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"DIDAuthenticateResponse" | b"ns4:DIDAuthenticateResponse" => {
                    in_did_authenticate = true;
                }
                b"MessageID" if in_did_authenticate => {
                    message_id = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read MessageID: {e}"))?
                            .to_string(),
                    );
                }
                b"RelatesTo" | b"wsa:RelatesTo" => {
                    relates_to = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read RelatesTo: {e}"))?
                            .to_string(),
                    );
                }
                b"Result" | b"ns2:Result" if in_did_authenticate => in_result = true,
                b"ResultMajor" | b"ns2:ResultMajor" if in_result => {
                    result_major = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read ResultMajor: {e}"))?
                        .to_string();
                }
                b"ResultMinor" | b"ns2:ResultMinor" if in_result => {
                    result_minor = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read ResultMinor: {e}"))?
                            .to_string(),
                    );
                }
                b"ResultMessage" | b"ns2:ResultMessage" if in_result => {
                    result_message = Some(
                        reader
                            .read_text(e.name())
                            .map_err(|e| format!("Failed to read ResultMessage: {e}"))?
                            .to_string(),
                    );
                }
                b"AuthenticationProtocolData" | b"ns4:AuthenticationProtocolData"
                    if in_did_authenticate =>
                {
                    in_auth_protocol = true;
                }
                b"CertificateHolderAuthorizationTemplate"
                    if in_auth_protocol =>
                {
                    phase = EACPhase::EAC1;
                    chat = reader
                        .read_text(e.name())
                        .map_err(|e| {
                            format!("Failed to read CertificateHolderAuthorizationTemplate: {e}")
                        })?
                        .to_string();
                }
                b"CertificationAuthorityReference"
                    if in_auth_protocol =>
                {
                    phase = EACPhase::EAC1;
                    car = reader
                        .read_text(e.name())
                        .map_err(|e| {
                            format!("Failed to read CertificationAuthorityReference: {e}")
                        })?
                        .to_string();
                }
                b"EFCardAccess" if in_auth_protocol => {
                    phase = EACPhase::EAC1;
                    ef_card_access = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read EFCardAccess: {e}"))?
                        .to_string();
                }
                b"IDPICC" if in_auth_protocol => {
                    phase = EACPhase::EAC1;
                    id_picc = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read IDPICC: {e}"))?
                        .to_string();
                }
                b"Challenge" if in_auth_protocol => {
                    phase = EACPhase::EAC1;
                    challenge = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read Challenge: {e}"))?
                        .to_string();
                }
                b"EFCardSecurity" if in_auth_protocol => {
                    phase = EACPhase::EAC2;
                    ef_card_security = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read EFCardSecurity: {e}"))?
                        .to_string();
                }
                b"AuthenticationToken" if in_auth_protocol => {
                    phase = EACPhase::EAC2;
                    authentication_token = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read AuthenticationToken: {e}"))?
                        .to_string();
                }
                b"Nonce" if in_auth_protocol => {
                    phase = EACPhase::EAC2;
                    nonce = reader
                        .read_text(e.name())
                        .map_err(|e| format!("Failed to read Nonce: {e}"))?
                        .to_string();
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"Result" | b"ns2:Result" => in_result = false,
                b"AuthenticationProtocolData" | b"ns4:AuthenticationProtocolData" => {
                    in_auth_protocol = false
                }
                b"DIDAuthenticateResponse" | b"ns4:DIDAuthenticateResponse" => {
                    in_did_authenticate = false
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if result_major.is_empty() {
        return Err("Missing ResultMajor in DIDAuthenticateResponse".to_string());
    }

    let eac1_output = if phase == EACPhase::EAC1 {
        if ef_card_access.is_empty() || id_picc.is_empty() || challenge.is_empty() {
            None
        } else {
            Some(EAC1OutputType {
                certificate_holder_authorization_template: Some(chat),
                certification_authority_reference: Some(vec![car]),
                ef_card_access,
                id_picc,
                challenge,
            })
        }
    } else {
        None
    };

    let eac2_output = if phase == EACPhase::EAC2
        && !ef_card_security.is_empty()
        && !authentication_token.is_empty()
        && !nonce.is_empty()
    {
        Some(EAC2OutputType::A {
            ef_card_security,
            authentication_token,
            nonce,
        })
    } else {
        None
    };

    Ok(PaosRequest::DIDAuthenticateResponse {
        message_id,
        relates_to,
        phase,
        eac1_output: Box::new(eac1_output),
        eac2_output,
        result_major,
        result_minor,
        result_message,
    })
}

pub async fn paos_handler<S>(
    State(state): State<AppState<S>>,
    body: String,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    S: EIDService + EidService + DIDAuthenticate + SessionManager + Send + Sync + 'static,
{
    debug!("Received PAOS request: {}", body);

    // Try parsing as StartPAOS first
    let paos_request = match parse_start_paos(&body) {
        Ok(request) => request,
        Err(start_err) => {
            debug!("Failed to parse as StartPAOS: {}", start_err);
            // Try parsing as DIDAuthenticateResponse
            match parse_did_authenticate_response(&body) {
                Ok(request) => request,
                Err(did_err) => {
                    error!(
                        "Failed to parse PAOS request: StartPAOS error: {}, DIDAuthenticateResponse error: {}. Raw request: {}",
                        start_err, did_err, body
                    );
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Failed to parse PAOS request: {did_err}"),
                    ));
                }
            }
        }
    };

    match paos_request {
        PaosRequest::StartPAOS {
            session_identifier,
            message_id,
            connection_handle,
        } => {
            if session_identifier.is_empty() {
                error!("Session identifier is empty in StartPAOS request");
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Session identifier is required".to_string(),
                ));
            }

            let message_id = match message_id {
                Some(id) if !id.is_empty() => id,
                _ => {
                    warn!(
                        "Message ID missing or empty in StartPAOS request. Using fallback UUID. Raw request: {}",
                        body
                    );
                    format!("urn:uuid:{}", Uuid::new_v4())
                }
            };

            debug!(
                "Parsed StartPAOS: session_id: {}, message_id: {}",
                session_identifier, message_id
            );

            let mut session_info = match state.use_id.get_session(&session_identifier).await {
                Ok(Some(info)) => info,
                Ok(None) => {
                    warn!("Invalid session identifier: {}", session_identifier);
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "Invalid session identifier".to_string(),
                    ));
                }
                Err(err) => {
                    error!("Session validation error: {}", err);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    ));
                }
            };

            if session_info.eac_phase != EACPhase::EAC1 {
                error!(
                    "Session {} is not in EAC1 phase: {:?}",
                    session_identifier, session_info.eac_phase
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Session not in EAC1 phase: {:?}", session_info.eac_phase),
                ));
            }

            state
                .use_id
                .update_session_connection_handles(
                    &session_identifier,
                    vec![connection_handle.card_application.clone()],
                )
                .await
                .map_err(|err| {
                    error!("Failed to update session connection handles: {}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to update session with connection handles".to_string(),
                    )
                })?;

            let temp_service =
                DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;

            let certs_chain_hex = temp_service
                .certificate_store
                .load_cv_chain()
                .await
                .map_err(|err| {
                    error!("Failed to load certificate chain: {}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to load certificate chain".to_string(),
                    )
                })?;

            if certs_chain_hex.is_empty() {
                error!("Certificate chain is empty");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Empty certificate chain".to_string(),
                ));
            }
            let mut certs = Vec::new();
            for hex in &certs_chain_hex {
                let cert = hex::decode(hex).map_err(|e| {
                    error!("Failed to decode cert: {e}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to decode cert".to_string(),
                    )
                })?;
                certs.push(cert);
            }
            let certificate_description = temp_service
                .certificate_store
                .generate_certificate_description(&certs)
                .map_err(|err| {
                    error!("Failed to generate certificate description: {}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to generate certificate description".to_string(),
                    )
                })?;

            let certificates_xml: String = certs_chain_hex
                .into_iter()
                .map(|cert| format!("<ns4:Certificate>{cert}</ns4:Certificate>"))
                .collect::<Vec<String>>()
                .join("");

            let server_outgoing_message_id = Uuid::new_v4().urn().to_string();

            // Update session_info with the server's outgoing message ID
            session_info.server_message_id = Some(server_outgoing_message_id.clone());
            state
                .use_id
                .store_session(session_info)
                .await
                .map_err(|err| {
                    error!("Failed to update session with server_message_id: {}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to update session".to_string(),
                    )
                })?;

            let paos_response = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                    <SOAP-ENV:Header>
                        <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                        <MessageID xmlns="http://www.w3.org/2005/03/addressing">{}</MessageID>
                    </SOAP-ENV:Header>
                    <SOAP-ENV:Body>
                        <ns4:DIDAuthenticate>
                            <ns4:ConnectionHandle>
                                <ns4:CardApplication>{}</ns4:CardApplication>
                                <ns4:SlotHandle>00</ns4:SlotHandle>
                            </ns4:ConnectionHandle>
                            <ns4:DIDName>PIN</ns4:DIDName>
                            <ns4:AuthenticationProtocolData xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Protocol="urn:oid:1.3.162.15480.3.0.14.2" xsi:type="ns4:EAC1InputType">
                                {}
                                <ns4:CertificateDescription>{}</ns4:CertificateDescription>
                                <ns4:RequiredCHAT>{}</ns4:RequiredCHAT>
                                <ns4:OptionalCHAT>{}</ns4:OptionalCHAT>
                                <ns4:AcceptedEIDType>CardCertified</ns4:AcceptedEIDType>
                            </ns4:AuthenticationProtocolData>
                        </ns4:DIDAuthenticate>
                    </SOAP-ENV:Body>
                </SOAP-ENV:Envelope>"#,
                message_id,
                server_outgoing_message_id,
                connection_handle.card_application,
                certificates_xml,
                certificate_description,
                EAC_REQUIRED_CHAT,
                EAC_OPTIONAL_CHAT
            );

            debug!("Generated PAOS response for EAC1: {}", paos_response);

            Ok((
                StatusCode::OK,
                [
                    ("Content-Type", "application/xml"),
                    ("PAOS-Version", "urn:liberty:paos:2006-08"),
                ],
                paos_response,
            ))
        }
        PaosRequest::DIDAuthenticateResponse {
            message_id,
            relates_to,
            phase,
            eac1_output,
            eac2_output,
            result_major,
            result_minor,
            result_message,
        } => {
            let message_id = message_id.unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()));

            // If result_major indicates an error, return the error response immediately
            if result_major.contains("error") {
                let result_minor = result_minor.unwrap_or_else(|| {
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#noPermission"
                        .to_string()
                });
                let result_message =
                    result_message.unwrap_or_else(|| "Authentication failed".to_string());

                let paos_response = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope 
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" 
                xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" 
                xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:StartPAOSResponse>
                        <ns2:Result>
                            <ns2:ResultMajor>{}</ns2:ResultMajor>
                            <ns2:ResultMinor>{}</ns2:ResultMinor>
                            <ns2:ResultMessage>{}</ns2:ResultMessage>
                        </ns2:Result>
                    </ns4:StartPAOSResponse>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>"#,
                    message_id,
                    Uuid::new_v4(),
                    result_major,
                    result_minor,
                    result_message
                );

                return Ok((
                    StatusCode::OK,
                    [
                        ("Content-Type", "application/xml"),
                        ("PAOS-Version", "urn:liberty:paos:2006-08"),
                    ],
                    paos_response,
                ));
            }

            let new_message_id = relates_to.ok_or_else(|| {
                error!("Missing RelatesTo header in DIDAuthenticateResponse");
                (
                    StatusCode::BAD_REQUEST,
                    "RelatesTo header is required".to_string(),
                )
            })?;

            // Validate session
            let mut session_info = match state
                .use_id
                .get_session_by_server_message_id(&new_message_id)
                .await
            {
                Ok(Some(info)) => info,
                Ok(None) => {
                    warn!("Session not found for RelatesTo: {new_message_id}");
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "Invalid or expired session".to_string(),
                    ));
                }
                Err(err) => {
                    error!("Session lookup error by RelatesTo: {}", err);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    ));
                }
            };

            let temp_service =
                DIDAuthenticateService::new_with_defaults(state.use_id.clone()).await;

            let mut signed_data = Vec::new();

            match phase {
                EACPhase::EAC1 => {
                    let eac1_output = eac1_output.ok_or_else(|| {
                        error!(
                            "Missing or incomplete EAC1 output fields in DIDAuthenticateResponse"
                        );
                        (
                            StatusCode::BAD_REQUEST,
                            "Missing or incomplete EAC1 output fields".to_string(),
                        )
                    })?;
                    let id_picc_bytes = hex::decode(&eac1_output.id_picc).unwrap();

                    signed_data.extend_from_slice(&id_picc_bytes);

                    let certs = temp_service
                        .certificate_store
                        .load_cv_chain()
                        .await
                        .map_err(|err| {
                            error!("Failed to load certificate chain: {err}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to load certificate chain".to_string(),
                            )
                        })?;

                    let term_cert_hex = certs[certs.len() - 1].clone();
                    let term_cert = hex::decode(&term_cert_hex).map_err(|err| {
                        error!("Failed to decode term certificate: {err}");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to decode term certificate".to_string(),
                        )
                    })?;

                    let cert_holder =
                        CertificateStore::extract_holder_reference(&term_cert).unwrap();

                    let term_key = temp_service
                        .certificate_store
                        .get_private_key(&cert_holder)
                        .await
                        .unwrap();

                    let (term_priv_key, public_key_bytes) = temp_service
                        .crypto_provider
                        .generate_keypair()
                        .await
                        .map_err(|err| {
                            error!("Failed to generate keypair: {}", err);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to generate keypair".to_string(),
                            )
                        })?;
                    let group = term_priv_key.group();
                    let mut ctx = BigNumContext::new().unwrap();
                    let point = EcPoint::from_bytes(group, &public_key_bytes, &mut ctx).unwrap();
                    let mut compressed = point
                        .to_bytes(group, PointConversionForm::COMPRESSED, &mut ctx)
                        .unwrap();
                    if compressed.len() == 33 {
                        compressed = compressed[1..].to_vec();
                    }

                    let public_key_hex = hex::encode(&public_key_bytes);

                    let pkey = PKey::from_ec_key(term_key.clone()).unwrap();
                    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
                    let challenge_bytes = hex::decode(eac1_output.challenge).unwrap();
                    signed_data.extend_from_slice(&challenge_bytes);
                    signed_data.extend_from_slice(&compressed);

                    signer.update(&signed_data).unwrap();

                    let der_sig = signer.sign_to_vec().unwrap();

                    let signature = EcdsaSig::from_der(&der_sig).unwrap();
                    let r_bytes = signature.r().to_vec_padded(32).unwrap();
                    let s_bytes = signature.s().to_vec_padded(32).unwrap();
                    let mut raw_sig = Vec::with_capacity(64);
                    raw_sig.extend(r_bytes);
                    raw_sig.extend(s_bytes);
                    let signature_hex = hex::encode(&raw_sig);

                    let paos_response = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                            <SOAP-ENV:Header>
                                <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                                <MessageID xmlns="http://www.w3.org/2005/03/addressing">{}</MessageID>
                            </SOAP-ENV:Header>
                            <SOAP-ENV:Body>
                                <ns4:DIDAuthenticate>
                                    <ns4:ConnectionHandle>
                                        <ns4:CardApplication>{}</ns4:CardApplication>
                                        <ns4:SlotHandle>00</ns4:SlotHandle>
                                    </ns4:ConnectionHandle>
                                    <ns4:DIDName>PIN</ns4:DIDName>
                                    <ns4:AuthenticationProtocolData Protocol="urn:oid:1.3.162.15480.3.0.14.3" xsi:type="ns4:EAC2InputType">
                                        <ns4:EphemeralPublicKey>{}</ns4:EphemeralPublicKey>
                                        <ns4:Signature>{}</ns4:Signature>
                                    </ns4:AuthenticationProtocolData>
                                </ns4:DIDAuthenticate>
                            </SOAP-ENV:Body>
                        </SOAP-ENV:Envelope>"#,
                        message_id,
                        new_message_id,
                        "e80704007f00070302",
                        // session_info
                        //     .connection_handles
                        //     .first()
                        //     .map(|h| h.connection_handle.clone())
                        //     .unwrap_or_default(),
                        public_key_hex,
                        signature_hex,
                        // dv_cert_hex
                    );

                    debug!("Generated PAOS response for EAC2: {}", paos_response);

                    Ok((
                        StatusCode::OK,
                        [
                            ("Content-Type", "application/xml"),
                            ("PAOS-Version", "urn:liberty:paos:2006-08"),
                        ],
                        paos_response,
                    ))
                }
                EACPhase::EAC2 => {
                    let eac2_output = eac2_output.ok_or_else(|| {
                        error!("Missing EAC2 output fields in DIDAuthenticateResponse");
                        (
                            StatusCode::BAD_REQUEST,
                            "Missing required EAC2 output fields".to_string(),
                        )
                    })?;

                    if let EAC2OutputType::A {
                        ef_card_security,
                        authentication_token,
                        nonce,
                    } = &eac2_output
                    {
                        if ef_card_security.is_empty()
                            || authentication_token.is_empty()
                            || nonce.is_empty()
                        {
                            error!("Incomplete EAC2 output: {:?}", eac2_output);
                            return Err((
                                StatusCode::BAD_REQUEST,
                                "Incomplete EAC2 output fields".to_string(),
                            ));
                        }

                        let auth_token_bytes =
                            hex::decode(authentication_token).map_err(|err| {
                                error!("Failed to decode authentication token: {}", err);
                                (
                                    StatusCode::BAD_REQUEST,
                                    "Invalid authentication token format".to_string(),
                                )
                            })?;

                        let nonce_bytes = hex::decode(&nonce).map_err(|err| {
                            error!("Failed to decode nonce: {err}");
                            (StatusCode::BAD_REQUEST, "Invalid nonce format".to_string())
                        })?;
                    } else {
                        error!("Unexpected EAC2 output type B");
                        return Err((
                            StatusCode::BAD_REQUEST,
                            "Unexpected EAC2 output type".to_string(),
                        ));
                    }

                    session_info.eac_phase = EACPhase::EAC2;
                    state
                        .use_id
                        .store_session(session_info)
                        .await
                        .map_err(|err| {
                            error!("Failed to update session: {}", err);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to update session".to_string(),
                            )
                        })?;

                    // EAC2 authentication completed successfully - now integrate transmit functionality
                    debug!("EAC2 authentication completed, initiating transmit functionality");

                    // Create a transmit request to continue the PAOS workflow
                    let transmit_request = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
                        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                            <SOAP-ENV:Header>
                                <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                                <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
                            </SOAP-ENV:Header>
                            <SOAP-ENV:Body>
                                <ns4:Transmit>
                                    <ns4:SlotHandle>00</ns4:SlotHandle>
                                    <ns4:InputAPDUInfo>
                                        <ns4:InputAPDU>00A4040C07A0000002471001</ns4:InputAPDU>
                                        <ns4:AcceptableStatusCode>9000</ns4:AcceptableStatusCode>
                                    </ns4:InputAPDUInfo>
                                </ns4:Transmit>
                            </SOAP-ENV:Body>
                        </SOAP-ENV:Envelope>"#,
                        message_id,
                        Uuid::new_v4()
                    );

                    // Process the transmit request through the integrated channel
                    match state.transmit_channel.handle_request(transmit_request.as_bytes()).await {
                        Ok(transmit_response_bytes) => {
                            let transmit_response = String::from_utf8_lossy(&transmit_response_bytes);
                            debug!("Transmit processing completed successfully within PAOS workflow");

                            // Return the transmit response as part of the PAOS workflow
                            Ok((
                                StatusCode::OK,
                                [
                                    ("Content-Type", "application/xml"),
                                    ("PAOS-Version", "urn:liberty:paos:2006-08"),
                                ],
                                transmit_response.to_string(),
                            ))
                        }
                        Err(e) => {
                            error!("Error in integrated transmit functionality: {}", e);

                            // Return error response in PAOS format
                            let error_response = format!(
                                r#"<?xml version="1.0" encoding="UTF-8"?>
                                <SOAP-ENV:Envelope
                                    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                                    xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema"
                                    xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                                    <SOAP-ENV:Header>
                                        <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                                        <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
                                    </SOAP-ENV:Header>
                                    <SOAP-ENV:Body>
                                        <ns4:StartPAOSResponse>
                                            <ns2:Result>
                                                <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error</ns2:ResultMajor>
                                                <ns2:ResultMessage>Transmit error: {}</ns2:ResultMessage>
                                            </ns2:Result>
                                        </ns4:StartPAOSResponse>
                                    </SOAP-ENV:Body>
                                </SOAP-ENV:Envelope>"#,
                                message_id,
                                Uuid::new_v4(),
                                e
                            );

                            let paos_response = format!(
                                r#"<?xml version="1.0" encoding="UTF-8"?>
                        <SOAP-ENV:Envelope
                            xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                            xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema"
                            xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                            <SOAP-ENV:Header>
                                <RelatesTo xmlns="http://www.w3.org/2005/03/addressing">{}</RelatesTo>
                                <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:{}</MessageID>
                            </SOAP-ENV:Header>
                            <SOAP-ENV:Body>
                                <ns4:StartPAOSResponse>
                                    <ns2:Result>
                                        <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                                        <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                                    </ns2:Result>
                                </ns4:StartPAOSResponse>
                            </SOAP-ENV:Body>
                        </SOAP-ENV:Envelope>"#,
                                message_id,
                                Uuid::new_v4()
                            );

                            debug!("Generated final StartPAOSResponse: {}", paos_response);

                            Ok((
                                StatusCode::OK,
                                [
                                    ("Content-Type", "application/xml"),
                                    ("PAOS-Version", "urn:liberty:paos:2006-08"),
                                ],
                                paos_response,
                            ))
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
    mod tests {
        use super::*;
        use crate::domain::eid::{
            service::{EIDServiceConfig, SessionInfo, UseidService},
            session_manager::InMemorySessionManager,
        };
    use axum::{
        Router,
        body::Body,
        http::{self, Request, StatusCode},
    };
    use chrono::{Duration, Utc};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    // Mock AppState for testing
    async fn create_test_state(session_id: &str) -> AppState<UseidService> {
        let session_manager = Arc::new(InMemorySessionManager::new()) as Arc<dyn SessionManager>;

        // Valid 32-byte hex-encoded PSK (64 characters)
        let valid_psk =
            "6db33c51c46bad9b4db72f131fd33442f57ebe6fd9f62c1346b836b30bd37d3d".to_string();

        let session_info = SessionInfo {
            id: session_id.to_string(),
            expiry: Utc::now() + chrono::Duration::minutes(5),
            psk: valid_psk,
            operations: vec![],
            connection_handles: vec![],
            eac_phase: crate::domain::eid::models::EACPhase::EAC1,
            eac1_challenge: None,
            server_message_id: None,
        };

        session_manager
            .store_session(session_info)
            .await
            .expect("Failed to store session");

        let use_id_service = UseidService {
            config: EIDServiceConfig {
                max_sessions: 10,
                session_timeout_minutes: 5,
                ecard_server_address: Some("https://test.eid.example.com".to_string()),
                redis_url: None,
            },
            session_manager,
        };

        let use_id_service_arc = Arc::new(use_id_service);

        // Create a mock transmit channel for testing
        use crate::domain::eid::transmit::{
            channel::TransmitChannel, protocol::ProtocolHandler, test_service::TestTransmitService,
        };
        use crate::config::TransmitConfig;
        use crate::server::session::SessionManager as ServerSessionManager;
        use std::time::Duration;

        let protocol_handler = ProtocolHandler::new();
        let session_manager = ServerSessionManager::new(Duration::from_secs(300));
        let transmit_service = Arc::new(TestTransmitService);
        let transmit_config = TransmitConfig::default();
        
        let transmit_channel = Arc::new(
            TransmitChannel::new(protocol_handler, session_manager, transmit_service, transmit_config)
                .expect("Failed to create test transmit channel")
        );

        AppState {
            use_id: Arc::clone(&use_id_service_arc),
            eid_service: Arc::clone(&use_id_service_arc),
            transmit_channel,
        }
    }

    // Test StartPAOS with valid session
    #[tokio::test]
    async fn test_start_paos_valid_session() {
        let session_id = "faf7554cf8a24e51a4dbfa9881121905";
        let state = create_test_state(session_id).await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = format!(
            r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:12345678-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:StartPAOS>
                        <ns4:SessionIdentifier>{session_id}</ns4:SessionIdentifier>
                        <ns4:ConnectionHandle>
                            <ns4:CardApplication>01</ns4:CardApplication>
                        </ns4:ConnectionHandle>
                    </ns4:StartPAOS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
            "#,
        );

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Expected 200 OK for valid StartPAOS request"
        );

        // Verify headers
        let headers = response.headers();
        assert_eq!(headers["Content-Type"], "application/xml");
        assert_eq!(headers["PAOS-Version"], "urn:liberty:paos:2006-08");

        // Verify response body contains DIDAuthenticate
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("<ns4:DIDAuthenticate>"));
        assert!(body_str.contains("<ns4:DIDName>PIN</ns4:DIDName>"));
        assert!(body_str.contains("urn:oid:1.3.162.15480.3.0.14.2"));
    }

    // Test StartPAOS with invalid session
    #[tokio::test]
    async fn test_start_paos_invalid_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:12345678-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:StartPAOS>
                        <ns4:SessionIdentifier>invalid_session</ns4:SessionIdentifier>
                        <ns4:ConnectionHandle>
                            <ns4:CardApplication>01</ns4:CardApplication>
                        </ns4:ConnectionHandle>
                    </ns4:StartPAOS>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 Unauthorized for invalid session"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert_eq!(body_str, "Invalid session identifier");
    }

    // Test DIDAuthenticateResponse without session identifier
    #[tokio::test]
    async fn test_did_authenticate_response_no_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
            <SOAP-ENV:Header>
                <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:98765432-1234-1234-1234-1234567890ab</MessageID>
            </SOAP-ENV:Header>
            <SOAP-ENV:Body>
                <ns4:DIDAuthenticateResponse>
                    <ns2:Result>
                        <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                        <ns2:ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success</ns2:ResultMinor>
                        <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                    </ns2:Result>
                    <ns4:AuthenticationProtocolData Protocol="urn:oid:1.3.162.15480.3.0.14.2" xsi:type="ns4:EAC1OutputType">
                        <ns4:CertificateHolderAuthorizationTemplate>7f4c12060904007f0007030102025305000503ff04</ns4:CertificateHolderAuthorizationTemplate>
                        <ns4:CertificationAuthorityReference>DETESTeID00005</ns4:CertificationAuthorityReference>
                        <ns4:EFCardAccess>3082010a020101...</ns4:EFCardAccess>
                        <ns4:IDPICC>1234567890abcdef</ns4:IDPICC>
                        <ns4:Challenge>66ad1219c486a165</ns4:Challenge>
                    </ns4:AuthenticationProtocolData>
                </ns4:DIDAuthenticateResponse>
            </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
    "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 Bad Request for missing session identifier"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert_eq!(body_str, "Session identifier is required");
    }

    // Test DIDAuthenticateResponse with invalid session
    #[tokio::test]
    async fn test_did_authenticate_response_invalid_session() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="urn:iso:std:iso-iec:24727:tech:schema">
                <SOAP-ENV:Header>
                    <MessageID xmlns="http://www.w3.org/2005/03/addressing">urn:uuid:98765432-1234-1234-1234-1234567890ab</MessageID>
                </SOAP-ENV:Header>
                <SOAP-ENV:Body>
                    <ns4:DIDAuthenticateResponse>
                        <ns4:SessionIdentifier>invalid_session</ns4:SessionIdentifier>
                        <ns2:Result>
                            <ns2:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns2:ResultMajor>
                            <ns2:ResultMinor>http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#success</ns2:ResultMinor>
                            <ns2:ResultMessage>Authentication successful</ns2:ResultMessage>
                        </ns2:Result>
                        <ns4:AuthenticationProtocolData Protocol="urn:oid:1.3.162.15480.3.0.14.2" xsi:type="ns4:EAC1OutputType">
                            <ns4:CertificateHolderAuthorizationTemplate>7f4c12060904007f0007030102025305000503ff04</ns4:CertificateHolderAuthorizationTemplate>
                            <ns4:CertificationAuthorityReference>DETESTeID00005</ns4:CertificationAuthorityReference>
                            <ns4:EFCardAccess>3081...</ns4:EFCardAccess>
                            <ns4:IDPICC>1234567890abcdef</ns4:IDPICC>
                            <ns4:Challenge>66ad1219c486a165</ns4:Challenge>
                        </ns4:AuthenticationProtocolData>
                    </ns4:DIDAuthenticateResponse>
                </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 Unauthorized for invalid session"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert_eq!(body_str, "Invalid session identifier");
    }

    // Test invalid XML
    #[tokio::test]
    async fn test_invalid_xml() {
        let state = create_test_state("valid_session").await;
        let app = Router::new()
            .route("/eIDService/paos", axum::routing::post(paos_handler))
            .with_state(state);

        let soap_request = r#"
            <?xml version="1.0" encoding="UTF-8"?>
            <InvalidXML>This is not a valid PAOS request</InvalidXML>
        "#;

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/eIDService/paos")
            .header("Content-Type", "application/xml")
            .header("PAOS-Version", "urn:liberty:paos:2006-08")
            .body(Body::from(soap_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 Bad Request for invalid XML"
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("Failed to collect body")
            .to_bytes();
        let body_str = String::from_utf8(body.to_vec()).expect("Failed to convert body to string");
        assert!(body_str.contains("Failed to parse PAOS request"));
    }
}
