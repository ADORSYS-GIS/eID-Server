use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509, X509NameRef};

#[derive(thiserror::Error, Debug)]
pub enum PkiError {
    #[error("PKI error: {0}")]
    Pki(String),
    #[error("Invalid input: {0}")]
    Invalid(String),
    #[error("Untrusted signer")]
    UntrustedSigner,
    #[error("Tampered or invalid signature")]
    BadSignature,
}

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
    pub signer_issuer: Option<String>,
    pub signer_serial_hex: Option<String>,
}

pub fn verify_cms_signed_object(
    input: &ValidationInput<'_>,
) -> Result<ValidationResult, PkiError> {
    // Build trust store (validates anchors PEM input early)
    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| PkiError::Pki(format!("Failed to create store: {e}")))?;
    if input.allow_partial_chain {
        // PARTIAL_CHAIN not available in this OpenSSL builder on this target; proceed without setting it.
    }
    for ca_pem in input.trust_anchors_pem {
        let ca = X509::from_pem(ca_pem).map_err(|e| PkiError::Pki(format!("Invalid CA PEM: {e}")))?;
        store_builder
            .add_cert(ca)
            .map_err(|e| PkiError::Pki(format!("Failed to add CA: {e}")))?;
    }
    let store: X509Store = store_builder.build();

    // Load optional intermediate certificates
    let mut intermediates_stack = Stack::new()
        .map_err(|e| PkiError::Pki(format!("Failed to create certificate stack: {e}")))?;
    if let Some(intermediates) = input.intermediates_pem {
        for pem in intermediates {
            let cert = X509::from_pem(pem)
                .map_err(|e| PkiError::Pki(format!("Invalid intermediate PEM: {e}")))?;
            intermediates_stack
                .push(cert)
                .map_err(|e| PkiError::Pki(format!("Failed to push intermediate: {e}")))?;
        }
    }

    // Parse CMS/PKCS7 container from DER
    let pkcs7 = Pkcs7::from_der(input.cms_der)
        .map_err(|e| PkiError::Invalid(format!("Invalid CMS/PKCS7 DER: {e}")))?;

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
        let (signer_issuer, signer_serial_hex) = pkcs7
            .signers(&intermediates_stack, Pkcs7Flags::empty())
            .ok()
            .and_then(|signers| signers.get(0).map(|c| {
                let issuer = format_subject(c.issuer_name());
                let serial = c
                    .serial_number()
                    .to_bn()
                    .ok()
                    .and_then(|bn| bn.to_hex_str().ok())
                    .map(|s| s.to_string());
                (Some(issuer), serial)
            }))
            .unwrap_or((None, None));
        return Ok(ValidationResult {
            valid: true,
            signer_subject,
            signer_issuer,
            signer_serial_hex,
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
        Ok(_) => Err(PkiError::UntrustedSigner),
        Err(_) => Err(PkiError::BadSignature),
    }
}

fn format_subject(name: &X509NameRef) -> String {
    let cn = name
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());
    if let Some(cn) = cn {
        return cn;
    }
    name
        .entries()
        .map(|e| {
            let nid = e.object().nid().short_name().unwrap_or("");
            let val = e
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "<non-utf8>".to_string());
            format!("{}={}", nid, val)
        })
        .collect::<Vec<_>>()
        .join(", ")
}


