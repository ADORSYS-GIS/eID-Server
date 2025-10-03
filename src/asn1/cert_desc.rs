use crate::asn1::oid::{HTML_FORMAT_OID, PDF_FORMAT_OID, PLAIN_FORMAT_OID};
use rasn::types::{
    Any, Ia5String, ObjectIdentifier as Oid, OctetString, PrintableString, SetOf, Utf8String,
};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};

/// Certificate Description as defined in TR-03110-4 $2.2.6
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CertificateDescription {
    /// Type of description (determines format of termsOfUsage)
    pub description_type: Oid,

    /// Name of the certificate issuer
    #[rasn(tag(explicit(1)))]
    pub issuer_name: Utf8String,

    /// Optional URL of the certificate issuer
    #[rasn(tag(explicit(2)))]
    pub issuer_url: Option<PrintableString>,

    /// Name of the certificate subject
    #[rasn(tag(explicit(3)))]
    pub subject_name: Utf8String,

    /// Optional URL of the certificate subject
    #[rasn(tag(explicit(4)))]
    pub subject_url: Option<PrintableString>,

    /// Terms of usage (format defined by description_type)
    #[rasn(tag(explicit(5)))]
    pub terms_of_usage: Any,

    /// Optional redirect URL
    #[rasn(tag(explicit(6)))]
    pub redirect_url: Option<PrintableString>,

    /// Optional set of communication certificate hashes
    #[rasn(tag(explicit(7)))]
    pub comm_certificates: Option<SetOf<OctetString>>,
}

impl Default for CertificateDescription {
    fn default() -> Self {
        Self {
            description_type: Oid::new_unchecked(PLAIN_FORMAT_OID.into()),
            issuer_name: Utf8String::from(""),
            issuer_url: None,
            subject_name: Utf8String::from(""),
            subject_url: None,
            terms_of_usage: Any::new(vec![]),
            redirect_url: None,
            comm_certificates: None,
        }
    }
}

/// Terms of usage in plain text format
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct PlainTermsOfUsage(pub Utf8String);

/// Terms of usage in HTML format
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct HtmlTermsOfUsage(pub Ia5String);

/// Terms of usage in PDF format
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct PdfTermsOfUsage(pub OctetString);

/// Enum for different types of terms of usage
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermsOfUsage {
    Plain(PlainTermsOfUsage),
    Html(HtmlTermsOfUsage),
    Pdf(PdfTermsOfUsage),
}

impl CertificateDescription {
    /// Create a new CertificateDescription with plain text terms of usage
    pub fn new_plain_terms(
        issuer_name: impl Into<String>,
        subject_name: impl Into<String>,
        terms: impl Into<String>,
    ) -> Self {
        let plain_oid = Oid::new_unchecked(PLAIN_FORMAT_OID.into());
        let plain_terms = PlainTermsOfUsage(terms.into());
        let terms_any = Any::new(rasn::der::encode(&plain_terms).unwrap());

        Self {
            description_type: plain_oid,
            issuer_name: issuer_name.into(),
            issuer_url: None,
            subject_name: subject_name.into(),
            subject_url: None,
            terms_of_usage: terms_any,
            redirect_url: None,
            comm_certificates: None,
        }
    }

    /// Create a new CertificateDescription with HTML terms of usage
    pub fn new_html_terms(
        issuer_name: impl Into<String>,
        subject_name: impl Into<String>,
        terms: impl Into<Ia5String>,
    ) -> Self {
        let html_oid = Oid::new_unchecked(HTML_FORMAT_OID.into());
        let html_terms = HtmlTermsOfUsage(terms.into());
        let terms_any = Any::new(rasn::der::encode(&html_terms).unwrap());

        Self {
            description_type: html_oid,
            issuer_name: issuer_name.into(),
            issuer_url: None,
            subject_name: subject_name.into(),
            subject_url: None,
            terms_of_usage: terms_any,
            redirect_url: None,
            comm_certificates: None,
        }
    }

    /// Create a new CertificateDescription with PDF terms of usage
    pub fn new_pdf_terms(
        issuer_name: impl Into<String>,
        subject_name: impl Into<String>,
        terms: impl Into<OctetString>,
    ) -> Self {
        let pdf_oid = Oid::new_unchecked(PDF_FORMAT_OID.into());
        let pdf_terms = PdfTermsOfUsage(terms.into());
        let terms_any = Any::new(rasn::der::encode(&pdf_terms).unwrap());

        Self {
            description_type: pdf_oid,
            issuer_name: issuer_name.into(),
            issuer_url: None,
            subject_name: subject_name.into(),
            subject_url: None,
            terms_of_usage: terms_any,
            redirect_url: None,
            comm_certificates: None,
        }
    }

    /// Set the issuer URL of the CertificateDescription
    pub fn with_issuer_url(mut self, url: impl Into<PrintableString>) -> Self {
        self.issuer_url = Some(url.into());
        self
    }

    /// Set the subject URL of the CertificateDescription
    pub fn with_subject_url(mut self, url: impl Into<PrintableString>) -> Self {
        self.subject_url = Some(url.into());
        self
    }

    /// Set the redirect URL of the CertificateDescription
    pub fn with_redirect_url(mut self, url: impl Into<PrintableString>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    /// Set the communication certificates of the CertificateDescription.
    ///
    /// May contain hash values of admissible X.509 certificates of the remote terminal.
    pub fn with_comm_certs(mut self, certs: impl Into<Vec<OctetString>>) -> Self {
        self.comm_certificates = Some(certs.into().into());
        self
    }

    /// Get the ASN.1 DER encoded bytes of this certificate description
    pub fn to_der(&self) -> Result<Vec<u8>, rasn::error::EncodeError> {
        rasn::der::encode(self)
    }

    /// Get the hex encoded DER bytes of this certificate description
    pub fn to_hex(&self) -> Result<String, rasn::error::EncodeError> {
        Ok(hex::encode(self.to_der()?))
    }
}
