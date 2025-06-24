use eid_server::{
    config::Config,
    domain::eid::service::{EIDServiceConfig, UseidService},
    server::{AppServerConfig, Server},
};

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };
    let eid_service = UseidService::new(EIDServiceConfig::default());

    let server_config = AppServerConfig {
        host: config.server.host,
        port: config.server.port,
    };

    let server = Server::new(eid_service, server_config.clone())
        .await
        .unwrap();

    let (port, handle) = server.run_with_port(server_config.clone()).await.unwrap();
    tokio::spawn(handle);

    format!("https://{}:{}", server_config.host, port)
}
