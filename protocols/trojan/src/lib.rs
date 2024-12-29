use common::{Addr, Network, ProxyConnection, SkipServerVerification};
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::{io::Result as IOResult, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};

const CRLF: &[u8; 2] = b"\r\n";

const CMD_CONNECT: u8 = 1;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/**
 * Datapack for trojan resquest message.
*/
#[derive(Debug)]
struct TrojanRequst {
    password: String,
    host: Addr,
    port: u16,
    payload: Vec<u8>,
}

impl TrojanRequst {
    fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in Sha224::digest(self.password.as_bytes()) {
            bytes.extend(format!("{:02x}", i).as_bytes());
        }
        bytes.extend(CRLF);

        /* Trojan Request */
        bytes.push(CMD_CONNECT);
        match &self.host {
            Addr::IPv4(addr) => {
                bytes.push(ATYP_IPV4);
                bytes.extend(addr);
            }
            Addr::Domain(domain) => {
                bytes.push(ATYP_DOMAIN);
                bytes.push(domain.len() as u8);
                bytes.extend(domain.as_bytes());
            }
            Addr::IPv6(addr) => {
                bytes.push(ATYP_IPV6);
                for u16num in addr {
                    bytes.extend(u16num.to_be_bytes());
                }
            }
        }
        bytes.extend(self.port.to_be_bytes());
        bytes.extend(CRLF);
        bytes.extend(&self.payload);

        bytes
    }
}

#[derive(Default)]
pub struct TrojanConnector {
    sni: Option<String>,
    insecure: bool,
    password: String,
}

impl TrojanConnector {
    pub fn sni(mut self, sni: &str) -> Self {
        self.sni = Some(sni.to_owned());
        self
    }
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_owned();
        self
    }
    pub async fn connect(
        self,
        host: &str,
        port: u16,
        dst: Addr,
        dst_port: u16,
    ) -> IOResult<TrojanClient> {
        let sock = TcpStream::connect(format!("{}:{}", host, port)).await?;

        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();

        if self.insecure {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
        }

        let sni = self.sni.unwrap_or(host.to_owned());

        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from(sni).unwrap();
        let tls = connector.connect(domain, sock).await?;

        Ok(TrojanClient {
            tls,
            password: self.password,
            dst,
            dst_port,
            connected: false,
        })
    }
}

/**
 * # Trojan client
 * Protocol details at <https://trojan-gfw.github.io/trojan/protocol>
*/
pub struct TrojanClient {
    pub tls: TlsStream<TcpStream>,
    dst: Addr,
    dst_port: u16,
    connected: bool,

    pub password: String,
}

impl ProxyConnection for TrojanClient {
    async fn receive(&mut self, buf: &mut [u8]) -> IOResult<(usize, common::Network)> {
        let size = self.tls.read(buf).await?;
        Ok((size, Network::Tcp))
    }
    async fn send(&mut self, buf: &[u8], _network: Network) -> IOResult<usize> {
        if !self.connected {
            let req = TrojanRequst {
                password: self.password.clone(),
                host: self.dst.clone(),
                port: self.dst_port,
                payload: buf.to_vec(),
            };
            self.connected = true;
            self.tls.write(&req.build()).await
        } else {
            self.tls.write(buf).await
        }
    }
}
