use std::sync::Arc;

use dashmap::DashMap;
use eid_server::domain::eid::service::EidService;
use eid_server::pki::identity::{FileIdentity, Identity};
use eid_server::pki::truststore::MemoryTrustStore;
use eid_server::session::{MemoryStore, SessionManager};
use eid_server::tls::{TestCertificates, TlsConfig, generate_test_certificates};
use eid_server::{config::Config, server::Server, telemetry};

pub async fn spawn_server(session_store: MemoryStore, tls_config: TlsConfig) -> String {
    telemetry::init_tracing();

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let session_manager = SessionManager::new(Arc::new(session_store));
    let file_identity = FileIdentity::new();
    let identity = Identity::new(file_identity.clone(), file_identity);
    let trust_store = MemoryTrustStore::new("./test_certs").await.unwrap();

    let service = EidService::new(session_manager, trust_store, identity);
    let server = Server::new(service, &config, tls_config).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("https://{}:{}", config.server.host, port)
}

#[allow(dead_code)]
pub fn create_tls_config(psk_store: DashMap<String, Vec<u8>>) -> TlsConfig {
    let TestCertificates {
        server_cert,
        server_key,
        ca_cert,
    } = generate_test_certificates();

    // build the tls configuration
    TlsConfig::from_pem(server_cert, server_key)
        .with_client_auth(&[ca_cert])
        .with_psk(psk_store)
}
