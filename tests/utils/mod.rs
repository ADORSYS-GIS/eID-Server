use dashmap::DashMap;
use eid_server::{
    config::Config,
    domain::eid::ports::{DIDAuthenticate, EIDService, EidService},
    server::Server,
    session::SessionStore,
    telemetry,
    tls::{TestCertificates, TlsConfig, generate_test_certificates},
};

pub async fn spawn_server(
    session_store: impl SessionStore + Clone + 'static,
    eid_service: impl EIDService + EidService + DIDAuthenticate,
    tls_config: TlsConfig,
) -> String {
    telemetry::init_tracing();

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let server = Server::new(session_store, eid_service, &config, tls_config)
        .await
        .unwrap();

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
