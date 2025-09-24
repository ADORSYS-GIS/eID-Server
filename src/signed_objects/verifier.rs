use crate::pki;
use crate::signed_objects::SignedObjectError;

pub use crate::pki::ValidationInput;

pub use crate::pki::ValidationResult;

pub fn verify_cms_signed_object(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, SignedObjectError> {
    pki::verify_cms_signed_object(input).map_err(|e| match e {
        pki::PkiError::Pki(msg) => SignedObjectError::Pki(msg),
        pki::PkiError::Invalid(msg) => SignedObjectError::Invalid(msg),
        pki::PkiError::UntrustedSigner => SignedObjectError::UntrustedSigner,
        pki::PkiError::BadSignature => SignedObjectError::BadSignature,
    })
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
