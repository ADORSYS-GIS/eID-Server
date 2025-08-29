use axum::{
    http::StatusCode,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};

const PAOS_CONTENT_TYPE: &str = "application/xml, charset=utf-8";

pub struct PaosResponse<T: Into<String>>(T);

impl<T: Into<String>> PaosResponse<T> {
    #[allow(dead_code)]
    pub fn new(data: T) -> Self {
        Self(data)
    }
}

impl<T: Into<String>> IntoResponse for PaosResponse<T> {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            [(CONTENT_TYPE, PAOS_CONTENT_TYPE)],
            self.0.into(),
        )
            .into_response()
    }
}
