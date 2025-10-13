use thiserror::Error;

/// Error type for defect list operations
#[derive(Debug, Error)]
pub enum DefectListError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    XmlParse(#[from] quick_xml::DeError),

    #[error("Document has defects: {reason}")]
    DocumentDefective { reason: String },

    #[error("Invalid defect list format: {0}")]
    InvalidFormat(String),

    #[error("Defect list not loaded")]
    NotLoaded,

    #[error(transparent)]
    Custom(#[from] color_eyre::eyre::Report),
}