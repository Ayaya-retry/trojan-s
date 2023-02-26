use std::net::{IpAddr, SocketAddr};
#[derive(Clone)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

pub struct Trojan {
    pwd: Vec<u8>,
    cmd: u8,
    address: Address,
    payload: Vec<u8>,
}

impl Trojan {
    pub const ADDR_TYPE_IPV4: u8 = 1;
    pub const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
    pub const ADDR_TYPE_IPV6: u8 = 4;

    pub fn new(pwd: Vec<u8>, cmd: u8, address: Address) -> Self {
        Self {
            pwd,
            cmd,
            address,
            payload: vec![],
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.append(&mut self.pwd);
        vec.append(&mut "\r\n".as_bytes().to_vec());
        vec.push(self.cmd);
        match &self.address {
            Address::SocketAddress(addr) => {
                match addr.ip() {
                    IpAddr::V4(v4) => {
                        vec.push(Self::ADDR_TYPE_IPV4);
                        vec.append(&mut v4.octets().to_vec());
                    }
                    IpAddr::V6(v6) => {
                        vec.push(Self::ADDR_TYPE_IPV6);
                        vec.append(&mut v6.octets().to_vec());
                    }
                }
                vec.append(&mut addr.port().to_be_bytes().to_vec());
            }
            Address::DomainNameAddress(domain, port) => {
                vec.push(domain.len() as u8);
                vec.append(&mut domain.as_bytes().to_vec());
                vec.append(&mut port.to_be_bytes().to_vec());
            }
        }
        vec.append(&mut "\r\n".as_bytes().to_vec());
        vec
    }

    pub fn password(&self) -> &Vec<u8> {
        &self.pwd
    }
    pub fn command(&self) -> &u8 {
        &self.cmd
    }
    pub fn address(&self) -> Address {
        self.address.clone()
    }
    pub fn add_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }
    pub fn payload(&self) -> &Vec<u8> {
        &self.payload
    }
    pub fn is_payload(&self) -> bool {
        !self.payload.is_empty()
    }
}
