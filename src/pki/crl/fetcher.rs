use std::time::Duration;

use reqwest::Client;
use tokio::time::timeout;
use tracing::info;
use url::Url;

use super::errors::{CrlError, CrlResult};
use super::types::CrlEntry;

/// Fetch CRL from a distribution point URL with timeout
pub async fn fetch_crl(
    client: &Client,
    distribution_point: &str,
    request_timeout: Duration,
) -> CrlResult<CrlEntry> {
    info!("Fetching CRL from: {}", distribution_point);

    // Validate URL
    Url::parse(distribution_point)
        .map_err(|_| CrlError::InvalidUrl(distribution_point.to_string()))?;

    // Fetch CRL with timeout
    let response = timeout(request_timeout, client.get(distribution_point).send())
        .await
        .map_err(|_| CrlError::Timeout)?
        .map_err(CrlError::Http)?;

    if !response.status().is_success() {
        return Err(CrlError::Custom(format!(
            "HTTP error {}: failed to fetch CRL from {}",
            response.status(),
            distribution_point
        )));
    }

    let crl_data = response.bytes().await.map_err(CrlError::Http)?.to_vec();

    // Parse CRL
    let crl_entry = CrlEntry::from_der(crl_data, distribution_point.to_string())?;

    // Validate CRL timing before returning
    if !crl_entry.is_valid() {
        return Err(CrlError::Expired);
    }

    info!(
        "Successfully fetched and validated CRL from {}",
        distribution_point
    );
    Ok(crl_entry)
}

/// Fetch CRLs from multiple distribution points in parallel
pub async fn fetch_crls_parallel(
    client: &Client,
    distribution_points: &[String],
    request_timeout: Duration,
) -> Vec<(String, CrlResult<CrlEntry>)> {
    let mut fetch_futures = Vec::new();

    for dp in distribution_points {
        let dp_clone = dp.clone();
        let client_clone = client.clone();
        let timeout_clone = request_timeout;

        fetch_futures.push(async move {
            let result = fetch_crl(&client_clone, &dp_clone, timeout_clone).await;
            (dp_clone, result)
        });
    }

    futures::future::join_all(fetch_futures).await
}
