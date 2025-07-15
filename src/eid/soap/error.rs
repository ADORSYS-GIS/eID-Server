use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoapError {
    #[error("XML serialization failed: {0}")]
    SerializationError(String),
    #[error("XML deserialization failed at {path}: {message}")]
    DeserializationError {
        path: String,
        message: String,
        source: Option<quick_xml::de::DeError>,
    },
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid value for field {field}: {value}")]
    InvalidValue { field: String, value: String },
}
