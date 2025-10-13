use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::pki::truststore::{MemoryTrustStore, TrustStore};

use super::errors::{CrlError, CrlResult};
use super::types::CrlData;

/// CRL processor - fetches CRLs and removes revoked certificates
pub struct CrlProcessor {
    client: Client,
    timeout: Duration,
}

impl CrlProcessor {
    /// Create a new CRL processor
    pub fn new(timeout_secs: u64) -> CrlResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;

        Ok(Self {
            client,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Fetch a CRL from a distribution point URL
    async fn fetch_crl(&self, url: &str) -> CrlResult<CrlData> {
        debug!("Fetching CRL from: {}", url);

        let response = match timeout(self.timeout, self.client.get(url).send()).await {
            Ok(result) => result?,
            Err(_) => return Err(CrlError::Timeout),
        };

        if !response.status().is_success() {
            return Err(CrlError::Custom(format!(
                "HTTP error {} when fetching CRL from {}",
                response.status(),
                url
            )));
        }

        let crl_data = response.bytes().await?.to_vec();
        CrlData::from_der(crl_data)
    }

    /// Process all CRLs from distribution points and remove revoked certificates
    pub async fn process_crls(
        &self,
        distribution_points: &[String],
        trust_store: &MemoryTrustStore,
    ) -> CrlResult<usize> {
        let mut total_removed = 0;

        for dp_url in distribution_points {
            match self.fetch_crl(dp_url).await {
                Ok(crl) => {
                    debug!("Successfully fetched CRL from {}", dp_url);

                    match crl.get_revoked_serials() {
                        Ok(revoked_serials) => {
                            debug!(
                                "Found {} revoked certificates in CRL",
                                revoked_serials.len()
                            );

                            // Remove each revoked certificate from trust store
                            for serial in revoked_serials {
                                match trust_store.remove_cert(&serial).await {
                                    Ok(true) => {
                                        debug!(
                                            "Removed revoked certificate with serial: {}",
                                            hex::encode(&serial)
                                        );
                                        total_removed += 1;
                                    }
                                    Ok(false) => {
                                        // Certificate not in trust store - ignore
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to remove certificate {}: {}",
                                            hex::encode(&serial),
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse revoked certificates from {}: {}",
                                dp_url, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch CRL from {}: {}", dp_url, e);
                    // Continue with other distribution points
                }
            }
        }

        debug!(
            "CRL processing complete. Removed {} revoked certificates",
            total_removed
        );
        Ok(total_removed)
    }
}
