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

    // Validate URL (uses #[from] url::ParseError)
    let _ = Url::parse(distribution_point)?;

    // Fetch CRL with timeout
    let response = match timeout(request_timeout, client.get(distribution_point).send()).await {
        Ok(result) => result?,
        Err(_) => return Err(CrlError::Timeout),
    };

    if !response.status().is_success() {
        return Err(CrlError::Custom(format!(
            "HTTP error {}: failed to fetch CRL from {}",
            response.status(),
            distribution_point
        )));
    }

    let crl_data = response.bytes().await?.to_vec();

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

/// Fetch CRLs from multiple distribution points in parallel using tokio tasks
pub async fn fetch_crls_parallel(
    client: &Client,
    distribution_points: &[String],
    request_timeout: Duration,
) -> Vec<(String, CrlResult<CrlEntry>)> {
    use tokio::task::JoinSet;

    let mut join_set = JoinSet::new();

    for dp in distribution_points {
        let dp_clone = dp.clone();
        let client_clone = client.clone();
        let timeout_clone = request_timeout;

        join_set.spawn(async move {
            let result = fetch_crl(&client_clone, &dp_clone, timeout_clone).await;
            (dp_clone, result)
        });
    }

    let mut results = Vec::with_capacity(distribution_points.len());

    while let Some(task_result) = join_set.join_next().await {
        match task_result {
            Ok(fetch_result) => results.push(fetch_result),
            Err(e) => {
                // Task panicked or was cancelled - this shouldn't happen in normal operation
                tracing::error!("Task failed to complete: {}", e);
            }
        }
    }

    results
}
