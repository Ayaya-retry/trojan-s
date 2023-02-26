use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor,
};

use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::{fs::File, io::BufReader, sync::Arc};

use crate::{
    config::Config,
    log,
    protocol::{parser_trojan, trojan},
};

pub async fn run(config: Config) {
    let listener = TcpListener::bind(config.local_host()).await.unwrap();
    let cer = certs(&mut BufReader::new(File::open(config.tls_cert()).unwrap()))
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys =
        pkcs8_private_keys(&mut BufReader::new(File::open(config.tls_key()).unwrap())).unwrap();
    if keys.len() == 0 {
        keys =
            rsa_private_keys(&mut BufReader::new(File::open(config.tls_key()).unwrap())).unwrap();
    }
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cer, PrivateKey(keys.remove(0)))
        .unwrap();

    let config = Arc::new(config);
    let server_config = Arc::new(server_config);
    log::out("server start success");
    loop {
        let config = config.clone();
        let accept = listener.accept().await;
        if let Err(_) = accept {
            log::out("accept error");
            continue;
        }
        let (stream, addr) = accept.unwrap();
        log::out(format!("{} connect success", addr).as_str());
        let accept = TlsAcceptor::from(server_config.clone())
            .accept(stream)
            .await;
        if let Err(_) = accept {
            log::out(format!("{} tls error", addr).as_str());
            continue;
        }
        let mut tls_stream = accept.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let read_len = tls_stream.read(&mut buf).await;
            let read_len = match read_len {
                Err(_) => {
                    if let Err(_) = tls_stream.shutdown().await {}
                    log::out("read header error");
                    return;
                }
                Ok(len) => len,
            };
            let buf = buf[..read_len].to_vec();

            let trojan = parser_trojan(buf.clone());
            let trojan = match trojan {
                Err(_) => {
                    log::out("not trojan forward remote");
                    match TcpStream::connect(config.remote_host()).await {
                        Ok(mut tcp_stream) => {
                            log::out(
                                format!("{:?} connect success", config.remote_host()).as_str(),
                            );
                            if let Err(_) = tcp_stream.write(&buf).await {}
                            relay_tcp(&mut tls_stream, &mut tcp_stream).await;
                        }
                        Err(_) => {
                            log::out(format!("{:?} connect error", config.remote_host()).as_str());
                            if let Err(_) = tls_stream.shutdown().await {}
                        }
                    };
                    return;
                }
                Ok(trojan) => trojan,
            };

            if *trojan.command() != 1 as u8 {
                log::out("command is not tcp");
                match TcpStream::connect(config.remote_host()).await {
                    Ok(mut tcp_stream) => {
                        if let Err(_) = tcp_stream.write(&buf).await {}
                        relay_tcp(&mut tls_stream, &mut tcp_stream).await;
                    }
                    Err(_) => if let Err(_) = tls_stream.shutdown().await {},
                };
                return;
            }

            if config.hash_pwd(trojan.password()) == false {
                log::out("passwd hash false");
                if let Err(_) = tls_stream.shutdown().await {}
                return;
            }

            match trojan.address() {
                trojan::Address::SocketAddress(addr) => {
                    let tcp_stream = TcpStream::connect(addr).await;
                    let mut tcp_stream = match tcp_stream {
                        Err(_) => {
                            log::out(format!("{:?} connect error", (addr.ip(), addr.port())).as_str());
                            if let Ok(_) = tls_stream.shutdown().await {}
                            return;
                        }
                        Ok(stream) => stream,
                    };

                    if trojan.is_payload() == true {
                        if let Err(_) = tcp_stream.write(trojan.payload()).await {}
                    }
                }
                trojan::Address::DomainNameAddress(domain, port) => {
                    let tcp_stream = TcpStream::connect((domain.clone(), port)).await;
                    let mut tcp_stream = match tcp_stream {
                        Err(_) => {
                            log::out(format!("{:?} connect error", (domain, port)).as_str());
                            if let Ok(_) = tls_stream.shutdown().await {}
                            return;
                        }
                        Ok(stream) => stream,
                    };

                    if trojan.is_payload() == true {
                        if let Err(_) = tcp_stream.write(trojan.payload()).await {}
                    }
                    relay_tcp(&mut tls_stream, &mut tcp_stream).await;
                }
            }
        });
    }
}

async fn relay_tcp<T: AsyncRead + AsyncWrite + Unpin>(s: &mut T, c: &mut TcpStream) {
    let (mut tls_r, mut tls_w) = split(s);
    let (mut tcp_r, mut tcp_w) = split(c);

    let t1 = async {
        let mut vec_buf = vec![0; 8192];
        loop {
            let len = if let Ok(len) = tls_r.read(&mut vec_buf).await {
                len
            } else {
                return;
            };
            if len == 0 {
                return;
            }
            if let Err(_) = tcp_w.write(&vec_buf[..len]).await {
                return;
            }
            if let Err(_) = tcp_w.flush().await {
                return;
            }
        }
    };

    let t2 = async {
        let mut vec_buf = vec![0; 8192];
        loop {
            let len = if let Ok(len) = tcp_r.read(&mut vec_buf).await {
                len
            } else {
                return;
            };
            if len == 0 {
                return;
            }
            if let Err(_) = tls_w.write(&vec_buf[..len]).await {
                return;
            }
            if let Err(_) = tls_w.flush().await {
                return;
            }
        }
    };

    let _ = tokio::select! {
        e = t1 => {e}
        e = t2 => {e}
    };
    let a = tls_r.unsplit(tls_w);
    let b = tcp_r.unsplit(tcp_w);
    if let Err(_) = a.shutdown().await {}
    if let Err(_) = b.shutdown().await {}
    log::out("connect shutdown");
}
