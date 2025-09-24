use crate::signed_objects::SignedObjectError;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509;
use openssl::x509::X509NameRef;
use openssl::nid::Nid;

#[derive(Debug, Clone)]
pub struct ValidationInput<'a> {
    pub cms_der: &'a [u8],
    pub trust_anchors_pem: &'a [&'a [u8]],
    pub intermediates_pem: Option<&'a [&'a [u8]]>,
    pub allow_partial_chain: bool,
}

fn format_subject(name: &X509NameRef) -> String {
    let cn = name.entries_by_nid(Nid::COMMONNAME).next().and_then(|e| e.data().as_utf8().ok()).map(|s| s.to_string());
    if let Some(cn) = cn { return cn; }
    name.entries().map(|e| {
        let nid = e.object().nid().short_name().unwrap_or("");
        let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_else(|_| "<non-utf8>".to_string());
        format!("{}={}", nid, val)
    }).collect::<Vec<_>>().join(", ")
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
    let store: X509Store = store_builder.build();

    // Load optional intermediate certificates
    let mut intermediates_stack = Stack::new()
        .map_err(|e| SignedObjectError::Pki(format!("Failed to create certificate stack: {e}")))?;
    if let Some(intermediates) = input.intermediates_pem {
        for pem in intermediates {
            let cert = X509::from_pem(pem)
                .map_err(|e| SignedObjectError::Pki(format!("Invalid intermediate PEM: {e}")))?;
            intermediates_stack
                .push(cert)
                .map_err(|e| SignedObjectError::Pki(format!("Failed to push intermediate: {e}")))?;
        }
    }

    // Parse CMS/PKCS7 container from DER
    let pkcs7 = Pkcs7::from_der(input.cms_der)
        .map_err(|e| SignedObjectError::Invalid(format!("Invalid CMS/PKCS7 DER: {e}")))?;

    // Verify signature and certificate path
    let mut out: Vec<u8> = Vec::new();
    let verify_result = pkcs7.verify(
        &intermediates_stack,
        &store,
        None,
        Some(&mut out),
        Pkcs7Flags::empty(),
    );

    if verify_result.is_ok() {
        // Extract signer subject if available
        let signer_subject = pkcs7
            .signers(&intermediates_stack, Pkcs7Flags::empty())
            .ok()
            .and_then(|signers| signers.get(0).map(|c| format_subject(c.subject_name())));
        return Ok(ValidationResult {
            valid: true,
            signer_subject,
        });
    }

    // Differentiate between trust failure and bad signature: try signature-only verify
    let mut out_sig_only: Vec<u8> = Vec::new();
    let sig_only = pkcs7.verify(
        &intermediates_stack,
        &store,
        None,
        Some(&mut out_sig_only),
        Pkcs7Flags::NOVERIFY,
    );

    match sig_only {
        Ok(_) => Err(SignedObjectError::UntrustedSigner),
        Err(_) => Err(SignedObjectError::BadSignature),
    }
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
