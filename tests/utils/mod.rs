use dashmap::DashMap;
use eid_server::domain::eid::service::EidService;
use eid_server::session::SessionManager;
use eid_server::tls::{TestCertificates, TlsConfig, generate_test_certificates};
use eid_server::{config::Config, server::Server, session::SessionStore, telemetry};

pub async fn spawn_server(
    session_store: impl SessionStore + Clone + 'static,
    tls_config: TlsConfig,
) -> String {
    telemetry::init_tracing();

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let session_manager = SessionManager::new(session_store);
    let service = EidService::new(session_manager);

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
    TlsConfig::new(server_cert, server_key)
        .with_client_auth(&[ca_cert], None::<&[u8]>)
        .with_psk(psk_store)
}
