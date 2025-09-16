use dotenv::dotenv;
use eid_server::{
    config::Config,
    pki::master_list::{
        CertificateValidator, FetcherConfig, MasterListFetcher, WebMasterListFetcher,
    },
};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize comprehensive logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Load .env file
    dotenv().ok();

    println!("=== REAL-TIME MASTER LIST TEST ===");
    info!("Starting real-time master list fetching test");

    // Step 1: Load configuration and display URL
    let config = Config::load().expect("Failed to load configuration");
    let master_list_url = &config.master_list.url;

    println!("Master List URL from .env: {master_list_url}");
    info!("Using master list URL from .env: {}", master_list_url);

    // Step 2: Create fetcher and attempt real network fetch
    let fetcher_config = FetcherConfig::default();
    let fetcher = WebMasterListFetcher::new(fetcher_config, config.master_list.clone())
        .expect("Failed to create web master list fetcher");

    println!("Fetching master list from configured URL (this may take a moment)...");
    info!("Attempting real network fetch from configured URL...");

    let master_list = match fetcher.fetch_master_list().await {
        Ok(ml) => {
            println!("✓ Successfully fetched master list from network!");
            info!("Successfully fetched master list from network");
            ml
        }
        Err(e) => {
            println!("✗ Failed to fetch master list: {e}");
            error!("Failed to fetch master list: {}", e);
            return Err(e.into());
        }
    };

    // Step 3: Display comprehensive master list information
    println!("\n=== FETCHED MASTER LIST DETAILS ===");
    println!("Version: {}", master_list.version);
    println!("Issue Date: {:?}", master_list.issue_date);
    println!("Next Update: {:?}", master_list.next_update);
    println!("Is Valid: {}", master_list.is_valid());
    println!("Total Countries: {}", master_list.csca_certificates.len());
    println!(
        "Total Link Certificates: {}",
        master_list.link_certificates.len()
    );

    // Step 4: Display detailed certificates by country
    println!("\n=== CERTIFICATES BY COUNTRY ===");
    let mut total_certificates = 0;
    let mut total_valid_certificates = 0;

    for (country_code, csca_list) in &master_list.csca_certificates {
        let valid_count = csca_list.iter().filter(|csca| csca.is_valid()).count();
        println!(
            "  {} -> {} certificates ({} valid)",
            country_code,
            csca_list.len(),
            valid_count
        );

        total_certificates += csca_list.len();
        total_valid_certificates += valid_count;

        // Show certificate details for first few countries
        if csca_list.len() <= 5 {
            for (i, csca) in csca_list.iter().enumerate() {
                let validity_status = if csca.is_valid() {
                    "VALID"
                } else {
                    "EXPIRED/INVALID"
                };
                println!(
                    "    Certificate #{}: {} ({})",
                    i + 1,
                    csca.fingerprint().unwrap_or_else(|_| "N/A".to_string())[..16].to_string()
                        + "...",
                    validity_status
                );
            }
        }
    }

    println!(
        "\nSUMMARY: {total_certificates} total certificates, {total_valid_certificates} valid certificates"
    );

    // Step 5: Display link certificates if available
    if !master_list.link_certificates.is_empty() {
        println!("\n=== LINK CERTIFICATES ===");
        for (i, link_cert) in master_list.link_certificates.iter().enumerate().take(10) {
            let validity_status = if link_cert.certificate_info.is_valid() {
                "VALID"
            } else {
                "EXPIRED/INVALID"
            };
            println!(
                "  Link #{}: {} -> {} ({})",
                i + 1,
                link_cert.source_country,
                link_cert.target_country,
                validity_status
            );
        }
        if master_list.link_certificates.len() > 10 {
            println!(
                "  ... and {} more link certificates",
                master_list.link_certificates.len() - 10
            );
        }
    }

    // Step 6: Test certificate validation
    println!("\n=== CERTIFICATE VALIDATION TEST ===");
    let validator = CertificateValidator::new().expect("Failed to create certificate validator");

    let mut validation_results = Vec::new();
    let mut successful_validations = 0;
    let max_certs_to_test = 5;
    let mut tested_count = 0;

    'outer: for (country_code, csca_list) in &master_list.csca_certificates {
        for csca in csca_list {
            if tested_count >= max_certs_to_test {
                break 'outer;
            }

            tested_count += 1;

            match csca.to_x509() {
                Ok(cert) => match validator.validate_certificate(&cert) {
                    Ok(is_valid) => {
                        if is_valid {
                            successful_validations += 1;
                            println!(
                                "  ✓ CSCA certificate for {country_code} validated successfully"
                            );
                        } else {
                            println!("  ✗ CSCA certificate for {country_code} validation failed");
                        }
                        validation_results.push(is_valid);
                    }
                    Err(e) => {
                        println!("  ✗ Error validating CSCA certificate for {country_code}: {e}");
                        validation_results.push(false);
                    }
                },
                Err(e) => {
                    println!("  ✗ Failed to convert CSCA to X509 for {country_code}: {e}");
                    validation_results.push(false);
                }
            }
        }
    }

    println!(
        "Validation Results: {successful_validations}/{tested_count} certificates validated successfully"
    );

    println!("\n=== REAL-TIME TEST COMPLETED SUCCESSFULLY ===");
    println!("The master list has been successfully fetched and processed!");

    Ok(())
}
