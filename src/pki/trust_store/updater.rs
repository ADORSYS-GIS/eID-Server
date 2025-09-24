use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hex;
use pem::Pem;
use reqwest::Client;
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::time::ASN1Time;

use crate::pki::trust_store::{
    certificate_manager::CertificateManager,
    error::TrustStoreError,
    models::{CSCAPublicKeyInfo, get_common_name},
};

/// Helper function to convert x509-parser's ASN1Time to chrono's DateTime<Utc>
fn asn1_time_to_chrono(asn1_time: ASN1Time) -> Result<DateTime<Utc>, TrustStoreError> {
    // Assuming asn1_time.to_datetime() returns time::OffsetDateTime directly based on the persistent error.
    let offset_datetime: OffsetDateTime = asn1_time.to_datetime();

    let system_time: std::time::SystemTime = offset_datetime.into();
    Ok(DateTime::<Utc>::from(system_time))
}

/// interface for fetching Master Lists.
#[async_trait]
#[mockall::automock]
pub trait MasterListFetcher {
    /// Fetches the master list from a given URL.
    /// Returns the raw content of the master list.
    async fn fetch_master_list(&self, url: &str) -> Result<Vec<u8>, TrustStoreError>;
}

/// An HTTP-based implementation of `MasterListFetcher`.
pub struct HttpMasterListFetcher {
    client: Client,
}

impl HttpMasterListFetcher {
    /// Creates a new `HttpMasterListFetcher`.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Default for HttpMasterListFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MasterListFetcher for HttpMasterListFetcher {
    async fn fetch_master_list(&self, url: &str) -> Result<Vec<u8>, TrustStoreError> {
        let response = self.client.get(url).send().await.map_err(|e| {
            TrustStoreError::UpdateError(format!("Failed to fetch master list from {url}: {e}"))
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(TrustStoreError::UpdateError(format!(
                "Failed to fetch master list from {url}: HTTP Status {status}"
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TrustStoreError::UpdateError(format!("Failed to read response body: {e}")))
    }
}

/// Manages updates to the trust store, including fetching and parsing Master Lists.
pub struct MasterListUpdater {
    fetcher: Box<dyn MasterListFetcher + Send + Sync>,
}

impl MasterListUpdater {
    /// Creates a new `MasterListUpdater`.
    pub fn new(fetcher: Box<dyn MasterListFetcher + Send + Sync>) -> Self {
        Self { fetcher }
    }

    /// Fetches and processes a master list, updating the certificate manager.
    pub async fn update_from_master_list(
        &self,
        manager: &mut CertificateManager,
        master_list_url: &str,
    ) -> Result<(), TrustStoreError> {
        println!("Fetching master list from: {}", master_list_url);
        let master_list_data = self.fetcher.fetch_master_list(master_list_url).await?;

        println!(
            "Received master list data ({} bytes). Parsing...",
            master_list_data.len()
        );

        let pem_certs = String::from_utf8(master_list_data).map_err(|e| {
            TrustStoreError::UpdateError(format!("Invalid UTF-8 in master list: {e}"))
        })?;

        let mut rest = pem_certs.as_bytes();
        while !rest.is_empty() {
            let (remaining, x509_pem_content) = parse_x509_pem(rest).map_err(|e| {
                TrustStoreError::UpdateError(format!("Failed to parse PEM block: {}", e))
            })?;

            let cert_der = x509_pem_content.contents;
            let cert_pem = pem::encode(&Pem::new("CERTIFICATE".to_string(), cert_der.to_vec()));

            let (_, parsed_cert) = parse_x509_certificate(&cert_der)
                .map_err(|e| TrustStoreError::CertificateParsingError(e.into()))?;

            let ski = hex::encode(
                parsed_cert
                    .tbs_certificate
                    .extensions()
                    .iter()
                    .find(|extension| {
                        extension.oid
                            == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
                    })
                    .ok_or_else(|| {
                        TrustStoreError::UpdateError(
                            "Failed to get subject key identifier extension".to_string(),
                        )
                    })?
                    .value,
            );

            let cert_info = CSCAPublicKeyInfo {
                subject_key_identifier: ski.clone(),
                certificate_pem: cert_pem,
                not_before: asn1_time_to_chrono(parsed_cert.tbs_certificate.validity.not_before)?,
                not_after: asn1_time_to_chrono(parsed_cert.tbs_certificate.validity.not_after)?,
                issuer_common_name: get_common_name(&parsed_cert.tbs_certificate.issuer),
                subject_common_name: get_common_name(&parsed_cert.tbs_certificate.subject),
            };

            manager.add_certificate(cert_info);
            println!("Added/Updated certificate: {}", ski);

            rest = remaining;
        }

        Ok(())
    }
}
