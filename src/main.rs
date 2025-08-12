use lark_messager::{config::Config, server::Server, AppResult};

#[tokio::main]
async fn main() -> AppResult<()> {
    let config = Config::from_env()?;
    let server = Server::new(config);
    server.run().await
}
