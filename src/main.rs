mod config;
mod service;
mod protocol;
mod utility;
mod log;
fn main() {
    let config = config::Config::new(String::from("./config/config.toml"));
    service::run(config);
}
