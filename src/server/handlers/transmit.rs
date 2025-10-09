use serde::Serialize;

use crate::{
    apdu::{APDUResponse, ProtectedAPDU, SecureMessaging},
    domain::models::{
        ProcessedAPDUResponse, State,
        paos::{StartPaosResponse, TransmitResponse},
    },
    pki::truststore::TrustStore,
    server::{
        AppState,
        errors::{AppError, PaosError},
        handlers::{SESSION_TRACKER, handle_paos_error},
    },
    session::SessionData,
    soap::{Envelope, Header},
};

#[derive(Debug, Serialize)]
struct StartPaosResp {
    #[serde(rename = "StartPAOSResponse")]
    value: StartPaosResponse,
}

pub async fn handle_transmit<T: TrustStore>(
    state: AppState<T>,
    envelope: Envelope<TransmitResponse>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, _, _) = get_ids(&envelope)?;

    match handle_inner(&state, envelope).await {
        Ok(result) => Ok(result),
        Err(e) => handle_paos_error(session_mgr, &session_id, e).await,
    }
}

async fn handle_inner<T: TrustStore>(
    state: &AppState<T>,
    envelope: Envelope<TransmitResponse>,
) -> Result<String, AppError> {
    let session_mgr = &state.service.session_manager;
    let (session_id, mapped_session_id, relates_to) = get_ids(&envelope)?;

    let mut session_data: SessionData = session_mgr
        .get(&*session_id)
        .await
        .map_err(AppError::paos_internal)?
        .ok_or(PaosError::Timeout)?;

    let State::Transmit {
        apdu_cmds,
        cmds_len,
        secure_keys,
    } = &session_data.state
    else {
        return Err(PaosError::Parameter("Expected state TransmitResponse".into()).into());
    };
    let body = envelope.into_body();

    // Validate request body
    let data = validate_transmit_body(body)?;

    // Process the APDU responses
    let processed_responses = process_apdu_responses(&data, apdu_cmds, *cmds_len, secure_keys)?;

    let message_id = uuid::Uuid::new_v4().urn().to_string();
    // Update the session tracker
    SESSION_TRACKER.invalidate(&mapped_session_id);
    SESSION_TRACKER.insert(message_id.clone(), session_id.clone());

    let header = Header {
        relates_to: Some(relates_to),
        message_id: Some(message_id),
    };

    // Update session state with processed responses
    session_data.state = State::TransmitResponse {
        responses: processed_responses,
    };
    session_mgr.insert(session_id, &session_data).await?;

    let resp = StartPaosResp {
        value: StartPaosResponse::ok(),
    };
    let result = Envelope::new(resp).with_header(header).serialize_paos(true);
    result.map_err(AppError::paos_internal)
}

fn get_ids(envelope: &Envelope<TransmitResponse>) -> Result<(String, String, String), AppError> {
    let mapped_id = envelope
        .header()
        .as_ref()
        .and_then(|h| h.relates_to.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());
    let session_id = SESSION_TRACKER
        .get(&mapped_id)
        .ok_or(PaosError::MissingPermissions)?;

    let relates_to = envelope
        .header()
        .as_ref()
        .and_then(|h| h.message_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().urn().to_string());

    Ok((session_id, mapped_id, relates_to))
}

fn validate_transmit_body(body: TransmitResponse) -> Result<TransmitResponse, AppError> {
    // Check for client errors
    if body.result.is_error() {
        return Err(AppError::paos_internal(PaosError::Parameter(format!(
            "Client respond with error: {:?}\nAborting session",
            body.result
        ))));
    }

    // Ensure required data are present
    if body.output_apdus.is_none() {
        return Err(AppError::Paos(PaosError::Parameter(
            "Missing  OutputAPDU in TransmitResponse".into(),
        )));
    }
    Ok(body)
}

/// Process APDU responses from the card
fn process_apdu_responses(
    data: &TransmitResponse,
    sent_commands: &[ProtectedAPDU],
    expected_count: usize,
    secure_keys: &Option<crate::domain::models::SecureMessagingKeys>,
) -> Result<Vec<ProcessedAPDUResponse>, AppError> {
    let output_apdus = data
        .output_apdus
        .as_ref()
        .ok_or_else(|| AppError::Paos(PaosError::Parameter("Missing output APDUs".into())))?;

    // Check if we received exactly the same number of responses as sent commands
    if output_apdus.len() != expected_count {
        return Err(AppError::Paos(PaosError::NodeNotReachable));
    }

    // Get secure messaging keys or return error if not available
    let keys = secure_keys.as_ref().ok_or_else(|| {
        AppError::Paos(PaosError::Parameter(
            "Secure messaging keys not available".into(),
        ))
    })?;

    let mut processed_responses = Vec::new();
    let mut sm = SecureMessaging::new(crate::apdu::SessionKeys {
        k_enc: keys.k_enc.clone().into(),
        k_mac: keys.k_mac.clone().into(),
        cipher: keys.to_cipher(),
    });

    // Set the initial SSC from the keys
    for _ in 0..keys.initial_ssc {
        sm.update_ssc();
    }

    for (_, (response_hex, sent_cmd)) in output_apdus.iter().zip(sent_commands.iter()).enumerate() {
        // Decode hex response
        let response_bytes = hex::decode(response_hex).map_err(|e| {
            AppError::Paos(PaosError::Parameter(format!("Invalid hex response: {}", e)))
        })?;

        // Parse APDU response
        let apdu_response = APDUResponse::from_bytes(&response_bytes).map_err(|e| {
            AppError::paos_internal(format!("Failed to parse APDU response: {}", e))
        })?;

        // Increase SSC twice before decrypting the response as per the card's expectation
        sm.update_ssc(); // First increment
        sm.update_ssc(); // Second increment

        // Decrypt the response using secure messaging
        let decrypted_response = sm
            .process_secure_response(&apdu_response)
            .map_err(|e| AppError::paos_internal(format!("Failed to decrypt response: {}", e)))?;

        // Extract status code and success flag before moving the data
        let status = decrypted_response.status();
        let status_code = status.0;
        let is_success = status == crate::apdu::StatusCode::SUCCESS;

        // Create processed response with metadata
        let processed_response = ProcessedAPDUResponse {
            response_data: decrypted_response.data,
            cmd_type: sent_cmd.cmd_type.clone(),
            ssc_before_cmd: sent_cmd.ssc_before_cmd,
            ssc_before_resp: sent_cmd.ssc_before_resp,
            status_code,
            is_success,
        };

        processed_responses.push(processed_response);
    }

    Ok(processed_responses)
}
