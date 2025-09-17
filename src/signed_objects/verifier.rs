use crate::signed_objects::SignedObjectError;
use openssl::x509::X509;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use tracing::warn;

#[derive(Debug, Clone)]
pub struct ValidationInput<'a> {
    pub cms_der: &'a [u8],
    pub trust_anchors_pem: &'a [&'a [u8]],
    pub intermediates_pem: Option<&'a [&'a [u8]]>,
    pub allow_partial_chain: bool,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub signer_subject: Option<String>,
}

pub fn verify_cms_signed_object(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, SignedObjectError> {
    // Build trust store (validates anchors PEM input early)
    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| SignedObjectError::Pki(format!("Failed to create store: {e}")))?;
    for ca_pem in input.trust_anchors_pem {
        let ca = X509::from_pem(ca_pem)
            .map_err(|e| SignedObjectError::Pki(format!("Invalid CA PEM: {e}")))?;
        store_builder
            .add_cert(ca)
            .map_err(|e| SignedObjectError::Pki(format!("Failed to add CA: {e}")))?;
    }
    let _store: X509Store = store_builder.build();

    // Note: CMS verification API is not available in this build context.
    warn!(
        "CMS verification not available in current OpenSSL feature set; returning UntrustedSigner"
    );
    Err(SignedObjectError::UntrustedSigner)
}

pub fn validate_master_list(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, SignedObjectError> {
    verify_cms_signed_object(input)
}

pub fn validate_defect_list(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, SignedObjectError> {
    verify_cms_signed_object(input)
}

pub fn validate_document_security_object(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, SignedObjectError> {
    verify_cms_signed_object(input)
}
