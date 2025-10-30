//! Certificate Revocation List (CRL) implementation
//!
//! This module provides CRL support according to ICAO 9303-12 §6.2
//!
//! # Features
//! - CRL fetching from configured distribution points
//! - Parsing CRL to extract revoked certificate serial numbers
//! - Removing revoked certificates from trust store
//! - Scheduled periodic CRL checking (daily at midnight)

use reqwest::Client;
use std::sync::Arc;
use thiserror::Error;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

use crate::config::CrlConfig;
use crate::pki::truststore::{TrustStore, TrustStoreError};

/// CRL-related errors
#[derive(Error, Debug)]
pub enum CrlError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("CRL parsing failed: {0}")]
    Parse(#[from] X509Error),

    #[error("Trust store error: {0}")]
    TrustStore(#[from] TrustStoreError),

    #[error("Scheduler error: {0}")]
    Scheduler(#[from] tokio_cron_scheduler::JobSchedulerError),

    #[error("{0}")]
    Custom(String),
}

/// Convenient Result type alias
pub type CrlResult<T> = Result<T, CrlError>;

/// CRL processor - fetches CRLs and removes revoked certificates
#[derive(Clone)]
pub struct CrlProcessor<T: TrustStore> {
    client: Client,
    truststore: T,
}

impl<T: TrustStore> CrlProcessor<T> {
    /// Create a new CRL processor
    pub fn new(_config: CrlConfig, truststore: T) -> CrlResult<Self> {
        let client = Client::builder().build()?;

        Ok(Self { client, truststore })
    }

    /// Fetch a CRL from a distribution point URL and return revoked serials
    async fn fetch_crl(&self, url: &str) -> CrlResult<Vec<Vec<u8>>> {
        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(CrlError::Custom(format!(
                "HTTP error {} when fetching CRL from {url}",
                response.status(),
            )));
        }

        let crl_data = response.bytes().await?.to_vec();

        // Parse DER-encoded bytes into a structured CertificateRevocationList object
        // from_der returns (remaining_bytes, parsed_crl) - we only need the parsed CRL
        let (_, crl) = CertificateRevocationList::from_der(&crl_data)
            .map_err(|e| CrlError::Parse(e.into()))?;

        let serials = crl
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .map(|revoked_cert| revoked_cert.user_certificate.to_bytes_be())
            .collect();

        Ok(serials)
    }

    /// Process all CRLs from distribution points and remove revoked certificates
    pub async fn process_crls(&self, distribution_points: &[String]) -> CrlResult<usize> {
        let mut total_removed = 0;

        for dp_url in distribution_points {
            let revoked_serials = match self.fetch_crl(dp_url).await {
                Ok(serials) => serials,
                Err(e) => {
                    warn!("Failed to fetch/parse CRL from {dp_url}: {e}");
                    continue;
                }
            };

            for serial in revoked_serials {
                if let Ok(true) = self.truststore.remove_cert(&serial).await {
                    total_removed += 1;
                }
            }
        }

        Ok(total_removed)
    }
}

/// Configuration for CRL scheduler
#[derive(Debug, Clone)]
pub struct CrlSchedulerConfig {
    /// CRL distribution point URLs
    pub distribution_points: CrlConfig,
    /// Whether to enable scheduler
    pub enable: bool,
}

impl Default for CrlSchedulerConfig {
    fn default() -> Self {
        Self {
            distribution_points: CrlConfig::default(),
            enable: true,
        }
    }
}

/// Scheduler for periodic CRL checking
pub struct CrlScheduler<T: TrustStore> {
    config: CrlSchedulerConfig,
    processor: Arc<CrlProcessor<T>>,
    scheduler: Arc<JobScheduler>,
}

impl<T: TrustStore + Clone + Send + Sync + 'static> CrlScheduler<T> {
    /// Create a new CRL scheduler
    pub async fn new(config: CrlSchedulerConfig, truststore: T) -> CrlResult<Self> {
        let processor = CrlProcessor::new(config.distribution_points.clone(), truststore.clone())?;
        let scheduler = Arc::new(JobScheduler::new().await?);

        Ok(Self {
            config,
            processor: Arc::new(processor),
            scheduler,
        })
    }

    /// Perform immediate CRL check
    pub async fn trigger_immediate_update(&self) -> CrlResult<usize> {
        debug!("Performing immediate CRL check");

        self.processor
            .process_crls(&self.config.distribution_points.distribution_points)
            .await
    }

    /// Start the scheduler - runs daily at midnight
    pub async fn start(self) -> CrlResult<()> {
        if !self.config.enable {
            info!("CRL scheduler disabled in configuration");
            return Ok(());
        }

        info!("Starting CRL scheduler to run daily at midnight (00:00:00)");

        let processor = self.processor.clone();
        let distribution_points = self.config.distribution_points.distribution_points.clone();

        // "0 0 0 * * *" = at 00:00:00 every day
        let job = Job::new_async("0 0 0 * * *", move |_uuid, _l| {
            let processor = processor.clone();
            let distribution_points = distribution_points.clone();

            Box::pin(async move {
                info!("Running scheduled CRL check (midnight)");

                processor
                    .process_crls(&distribution_points)
                    .await
                    .map_err(|e| error!("Scheduled CRL check failed: {e}"))
                    .ok();
            })
        })?;

        self.scheduler.add(job).await?;
        self.scheduler.start().await?;

        info!("CRL scheduler started successfully - will run daily at midnight");

        Ok(())
    }
}
