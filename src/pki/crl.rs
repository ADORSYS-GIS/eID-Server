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

/// Represents a Certificate Revocation List
#[derive(Debug, Clone)]
pub struct CrlData {
    /// The raw CRL data in DER format
    pub der_data: Vec<u8>,
}

impl CrlData {
    /// Create a new CRL from DER data
    pub fn from_der(der_data: Vec<u8>) -> Result<Self, CrlError> {
        // Validate that we can parse it
        let _ = CertificateRevocationList::from_der(&der_data)
            .map_err(|e| CrlError::Parse(e.into()))?;

        Ok(Self { der_data })
    }

    /// Parse the CRL from DER data
    fn parse<'a>(&'a self) -> Result<CertificateRevocationList<'a>, CrlError> {
        let (_, crl) = CertificateRevocationList::from_der(&self.der_data)
            .map_err(|e| CrlError::Parse(e.into()))?;
        Ok(crl)
    }

    /// Get list of revoked certificate serial numbers
    pub fn get_revoked_serials(&self) -> Result<Vec<Vec<u8>>, CrlError> {
        let crl = self.parse()?;

        let serials: Vec<Vec<u8>> = crl
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .map(|revoked_cert| revoked_cert.user_certificate.to_bytes_be())
            .collect();

        Ok(serials)
    }
}

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

    /// Fetch a CRL from a distribution point URL
    async fn fetch_crl(&self, url: &str) -> CrlResult<CrlData> {
        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(CrlError::Custom(format!(
                "HTTP error {} when fetching CRL from {url}",
                response.status(),
            )));
        }

        let crl_data = response.bytes().await?.to_vec();

        CrlData::from_der(crl_data)
    }

    /// Process all CRLs from distribution points and remove revoked certificates
    pub async fn process_crls(&self, distribution_points: &[String]) -> CrlResult<usize> {
        let mut total_removed = 0;

        for dp_url in distribution_points {
            let crl = match self.fetch_crl(dp_url).await {
                Ok(crl) => crl,
                Err(e) => {
                    warn!("Failed to fetch CRL from {dp_url}: {e}");
                    continue;
                }
            };

            let revoked_serials = match crl.get_revoked_serials() {
                Ok(serials) => serials,
                Err(e) => {
                    warn!("Failed to parse revoked certificates from {dp_url}: {e}");
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

        // Cron expression: Run at midnight (00:00:00) every day
        let job = Job::new_async("0 0 0 * * *", move |_uuid, _l| {
            let processor = processor.clone();
            let distribution_points = distribution_points.clone();

            Box::pin(async move {
                info!("Running scheduled CRL check (midnight)");

                match processor.process_crls(&distribution_points).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Scheduled CRL check failed: {e}");
                    }
                }
            })
        })?;

        self.scheduler.add(job).await?;
        self.scheduler.start().await?;

        info!("CRL scheduler started successfully");

        Ok(())
    }
}
