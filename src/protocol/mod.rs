use crate::utility;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod trojan;

pub fn parser_trojan(buf: Vec<u8>) -> Result<trojan::Trojan, ()> {
    let pos = utility::search_u8_vec(&buf, &"\r\n".as_bytes().to_vec());
    if let None = pos {
        return Err(());
    }
    let pos = pos.unwrap();

    let pwd = &buf[..pos];
    let header = &buf[pos + 2..];
    let mut offset = 0;
    let cmd = header[offset];
    offset += 1;
    let addr_type = header[offset];
    offset += 1;
    let address = match addr_type {
        trojan::Trojan::ADDR_TYPE_IPV4 => {
            let v4 = &header[offset..];
            let addr = Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]);
            let port = (v4[4] as u16) << 8 | v4[5] as u16;
            offset += 5;
            Ok(trojan::Address::SocketAddress(SocketAddr::new(
                IpAddr::V4(addr),
                port,
            )))
        }
        trojan::Trojan::ADDR_TYPE_IPV6 => {
            let v6 = &header[offset..];
            let addr = Ipv6Addr::new(
                (v6[0] as u16) << 8 | v6[1] as u16,
                (v6[3] as u16) << 8 | v6[4] as u16,
                (v6[5] as u16) << 8 | v6[6] as u16,
                (v6[7] as u16) << 8 | v6[8] as u16,
                (v6[9] as u16) << 8 | v6[10] as u16,
                (v6[11] as u16) << 8 | v6[12] as u16,
                (v6[13] as u16) << 8 | v6[14] as u16,
                (v6[15] as u16) << 8 | v6[16] as u16,
            );
            let port = (v6[17] as u16) << 8 | v6[18] as u16;
            offset += 18;
            Ok(trojan::Address::SocketAddress(SocketAddr::new(
                IpAddr::V6(addr),
                port,
            )))
        }
        trojan::Trojan::ADDR_TYPE_DOMAIN_NAME => {
            let domain = &header[offset..];
            let len = domain[0] as usize;
            let addr = String::from_utf8(domain[1..len + 1].to_vec());
            if let Ok(addr) = addr {
                let port = (domain[len + 1] as u16) << 8 | domain[len + 2] as u16;
                offset += len + 2;
                Ok(trojan::Address::DomainNameAddress(addr, port))
            } else {
                Err(())
            }
        }
        _ => Err(()),
    };

    if let Err(_) = address {
        return Err(());
    }

    let address = address.unwrap();

    let mut trojan = trojan::Trojan::new(pwd.to_vec(), cmd, address);
    if header.len() > offset + 3 {
        let payload = &header[offset + 3..];
        trojan.add_payload(payload.to_vec());
    }
    Ok(trojan)
}
