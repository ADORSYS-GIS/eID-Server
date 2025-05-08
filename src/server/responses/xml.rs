use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use quick_xml::se::to_string;
use serde::Serialize;

/// XML response type for Axum
pub struct Xml<T>(pub T);

impl<T> IntoResponse for Xml<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response<Body> {
        match to_string(&self.0) {
            Ok(xml) => {
                let mut response = Response::new(Body::from(xml));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml; charset=utf-8"),
                );
                response
            }
            Err(err) => {
                tracing::error!("Failed to serialize to XML: {}", err);
                let mut response = Response::new(Body::from(format!(
                    "Failed to serialize the response to XML: {}",
                    err
                )));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
            }
        }
    }
}
