use crate::config::{Config, RunType};

mod client;
mod server;

#[tokio::main]
pub async fn run(config: Config) {
    if let Ok(run_type) = config.run_type() {
        match run_type {
            RunType::Server => server::run(config).await,
            RunType::Client => client::run(config).await,
        }
    }
}
