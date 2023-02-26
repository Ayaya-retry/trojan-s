use serde::Deserialize;
use sha2::{Digest, Sha224};
use std::fs::File;
use std::io::Read;
pub enum RunType {
    Server,
    Client,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    run_type: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    password: Vec<String>,
    log_level: u8,
    tls: Tls,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Tls {
    cert: String,
    key: String,
}

impl Config {
    pub fn new(path: String) -> Config {
        let mut file = File::open(path).unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        let mut config = toml::from_str::<Self>(&buffer).unwrap();
        let mut hash_pwd: Vec<String> = vec![];
        for pwd in config.password {
            let mut hash = Sha224::new();
            hash.update(&pwd.into_bytes());
            let h = hash.finalize();
            let hex = format!("{:x}", h);
            hash_pwd.push(hex);
        }
        config.password = hash_pwd;
        config
    }

    pub fn run_type(&self) -> Result<RunType, ()> {
        match self.run_type.as_str() {
            "Server" => Ok(RunType::Server),
            "Client" => Ok(RunType::Client),
            _ => Err(()),
        }
    }
    pub fn local_host(&self) -> (String, u16) {
        (self.local_addr.clone(), self.local_port.clone())
    }
    pub fn remote_host(&self) -> (String, u16) {
        (self.remote_addr.clone(), self.remote_port.clone())
    }

    pub fn hash_pwd(&self, pwd: &Vec<u8>) -> bool {
        if let Some(_) = self.password.iter().find(|&arg| arg.as_bytes() == pwd) {
            true
        } else {
            false
        }
    }
    pub fn tls_cert(&self) -> String {
        self.tls.cert.clone()
    }
    pub fn tls_key(&self) -> String {
        self.tls.key.clone()
    }
}
