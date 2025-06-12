use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{Server, ServerConfig},
    sal::transmit::config::TransmitConfig,
};

// Helper function to spawn a test server on a random port
pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        // Use a random OS port
        config.server.port = 0;
        config
    };
    let eid_service = UseidService::new(EIDServiceConfig::default());

    let server_config = ServerConfig {
        host: &config.server.host,
        port: config.server.port,
        transmit: TransmitConfig::default(),
    };

    let server = Server::new(eid_service, server_config.clone())
        .await
        .unwrap();

    let port = server.port().unwrap();
    tokio::spawn(async move {
        server.run().await.expect("failed to run server");
    });

    format!("http://{}:{}", server_config.host, port)
}
