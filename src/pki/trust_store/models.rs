use std::borrow::Cow;
use std::fmt;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use x509_parser::oid_registry::Oid;
use x509_parser::x509::AttributeTypeAndValue;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CSCAPublicKeyInfo {
    pub subject_key_identifier: String,
    pub certificate_pem: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer_common_name: Option<String>,
    pub subject_common_name: Option<String>,
}

impl fmt::Display for CSCAPublicKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CSCA Cert: SKI={}, Issuer CN={:?}, Subject CN={:?}, Valid from {} to {}",
            self.subject_key_identifier,
            self.issuer_common_name,
            self.subject_common_name,
            self.not_before,
            self.not_after
        )
    }
}

static CN_OID: Lazy<Oid<'static>> = Lazy::new(|| Oid::new(Cow::Borrowed(&[2, 5, 4, 3])));

// Helper to extract Common Name from an X.509 Name
pub fn get_common_name(name: &x509_parser::x509::X509Name) -> Option<String> {
    name.iter_by_oid(&CN_OID)
        .filter_map(|attr_type_and_value: &AttributeTypeAndValue| {
            attr_type_and_value.as_str().map(String::from).ok()
        })
        .next()
}
