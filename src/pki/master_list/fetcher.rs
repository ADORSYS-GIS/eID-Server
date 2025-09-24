use async_trait::async_trait;
use reqwest::Client;

use crate::pki::trust_store::error::TrustStoreError;

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
