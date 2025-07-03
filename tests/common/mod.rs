use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{Server, ServerConfig},
};

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };
    let eid_service = UseidService::new(EIDServiceConfig::default());

    // Create ServerConfig with reference to config values
    let server_config = ServerConfig {
        host: &config.server.host,
        port: config.server.port,
    };

    // Create server without TLS
    let server = Server::new(eid_service, server_config, None)
        .await
        .unwrap();

    // Get the port the server is bound to
    let port = server.port().unwrap();

    // Return HTTP address (since we're not using TLS in tests)
    format!("http://{}:{}", config.server.host, port)
}
