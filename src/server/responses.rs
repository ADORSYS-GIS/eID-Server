use axum::{
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};

use crate::{domain::models::errors::AppError, soap::Envelope};

const APP_CONTENT_TYPE: &str = "text/xml; charset=utf-8";
const INTERNAL_ERROR_MESSAGE: &str = "The server encountered an internal error.";

pub struct SoapResponse<T: Into<String>>(T);

impl<T: Into<String>> SoapResponse<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Into<String>> IntoResponse for SoapResponse<T> {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            [(CONTENT_TYPE, APP_CONTENT_TYPE)],
            self.0.into(),
        )
            .into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match Envelope::new(self.to_result()).serialize_soap(true) {
            Ok(xml) => SoapResponse::new(xml).into_response(),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to serialize XML error response");
                (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR_MESSAGE).into_response()
            }
        }
    }
}
