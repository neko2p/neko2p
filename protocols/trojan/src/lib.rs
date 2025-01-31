use bytes::BufMut;
use common::{
    utils::Buf, Addr, Network, ProxyConnection, ProxyHandshake, ProxyServer, SkipServerVerification,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::ToSocketAddrs,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore, ServerConfig},
    TlsAcceptor, TlsConnector,
};

const UDP_MAX_PACK_SIZE: usize = 65535;

const CRLF: &[u8; 2] = b"\r\n";

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const PASSWORD_SHA224_LEN: usize = 56;

fn sha224_hex_kdf(password: &str) -> String {
    use sha2::{Digest, Sha224};

    let mut sha224_sum = String::new();
    for i in Sha224::digest(password.as_bytes()) {
        sha224_sum.push_str(&format!("{:02x}", i));
    }

    sha224_sum
}

/**
 * Datapack for trojan resquest message.
 */
#[derive(Debug)]
struct TrojanRequst {
    password: String,
    host: Addr,
    port: u16,
    cmd: u8,
}

impl TrojanRequst {
    fn build_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.put_slice(self.password.as_bytes());
        packet.put_slice(CRLF);

        /* Trojan Request */
        packet.put_u8(self.cmd);
        match &self.host {
            Addr::IPv4(addr) => {
                packet.put_u8(ATYP_IPV4);
                packet.put_slice(addr);
            }
            Addr::Domain(domain) => {
                packet.put_u8(ATYP_DOMAIN);
                packet.put_u8(domain.len() as u8);
                packet.put_slice(domain.as_bytes());
            }
            Addr::IPv6(addr) => {
                packet.put_u8(ATYP_IPV6);
                for u16num in addr {
                    packet.put_u16(*u16num);
                }
            }
        }
        packet.put_u16(self.port);
        packet.put_slice(CRLF);
        packet.put_slice(payload);

        packet
    }
    async fn receive_parse<T>(mut stream: T) -> IOResult<Self>
    where
        T: AsyncRead + Unpin,
    {
        let mut password = String::new();
        for _ in 0..PASSWORD_SHA224_LEN {
            password.push(stream.read_u8().await? as char);
        }
        stream.read_u16().await?; // CRLF
        let cmd = stream.read_u8().await?; // CMD

        let host;
        let atype = stream.read_u8().await?;
        match atype {
            ATYP_IPV4 => {
                let mut ipv4 = [0; 4];
                for i in &mut ipv4 {
                    *i = stream.read_u8().await?;
                }
                host = Addr::IPv4(ipv4);
            }
            ATYP_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = stream.read_u16().await?;
                }
                host = Addr::IPv6(ipv6);
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(stream.read_u8().await? as char);
                }
                host = Addr::Domain(domain);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("Invalid ATYPE {}", atype),
                ))
            }
        }

        let port = stream.read_u16().await?;
        stream.read_u16().await?; // CRLF

        Ok(Self {
            password,
            host,
            port,
            cmd,
        })
    }
}

struct UdpPacket {
    host: Addr,
    port: u16,
    payload: Vec<u8>,
}

impl UdpPacket {
    fn parse_packet(mut bytes: &[u8]) -> IOResult<Self> {
        let atype = bytes.get_u8()?;
        let host;
        match atype {
            ATYP_IPV4 => {
                let mut ipv4 = [0; 4];
                for i in &mut ipv4 {
                    *i = bytes.get_u8()?;
                }
                host = Addr::IPv4(ipv4);
            }
            ATYP_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = bytes.get_u16()?;
                }
                host = Addr::IPv6(ipv6);
            }
            ATYP_DOMAIN => {
                let len = bytes.get_u8()? as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(bytes.get_u8()? as char);
                }
                host = Addr::Domain(domain);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("Invalid ATYPE {}", atype),
                ))
            }
        }
        let port = bytes.get_u16()?;
        bytes.get_u16()?; // size
        bytes.get_u16()?; // CRLF
        Ok(Self {
            host,
            port,
            payload: bytes.to_owned(),
        })
    }
    fn build_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        match &self.host {
            Addr::IPv4(addr) => {
                packet.put_u8(ATYP_IPV4);
                packet.put_slice(addr);
            }
            Addr::Domain(domain) => {
                packet.put_u8(ATYP_DOMAIN);
                packet.put_u8(domain.len() as u8);
                packet.put_slice(domain.as_bytes());
            }
            Addr::IPv6(addr) => {
                packet.push(ATYP_IPV6);
                for u16num in addr {
                    packet.put_u16(*u16num);
                }
            }
        }
        packet.put_u16(self.port);
        packet.put_u16(self.payload.len() as u16);
        packet.put_slice(CRLF);
        packet.put_slice(&self.payload);

        packet
    }
}

#[derive(Default)]
pub struct TrojanConnector {
    sni: Option<String>,
    insecure: bool,
    sha224_password: String,
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
        self.sha224_password = sha224_hex_kdf(password);
        self
    }
    pub async fn connect<A>(
        self,
        addr: A,
        dst: Addr,
        dst_port: u16,
    ) -> IOResult<impl ProxyConnection>
    where
        A: ToSocketAddrs,
    {
        let sock = TcpStream::connect(addr).await?;

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

        let sni = self.sni.unwrap_or_default();

        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from(sni).unwrap();
        let tls = connector.connect(domain, sock).await?;

        Ok(TrojanClient {
            tls,
            password: self.sha224_password,
            dst,
            dst_port,
            connected: false,
            is_udp: false,
        })
    }
}

#[derive(Default)]
pub struct TrojanServerBuilder {
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: Option<PrivateKeyDer<'static>>,
    sha224_passwords: Vec<String>,
}

impl TrojanServerBuilder {
    pub fn add_cert_chain(mut self, pem: &[u8]) -> Self {
        self.cert_chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        self
    }
    pub fn add_key_der(mut self, pem: &[u8]) -> Self {
        self.key_der = Some(PrivateKeyDer::from_pem_slice(pem).unwrap());
        self
    }
    pub fn add_password(mut self, password: &str) -> Self {
        self.sha224_passwords.push(sha224_hex_kdf(password));
        self
    }
    pub async fn listen<A>(self, bind_addr: A) -> IOResult<TrojanServer>
    where
        A: ToSocketAddrs,
    {
        let listener = TcpListener::bind(bind_addr).await?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain, self.key_der.unwrap())
            .unwrap();
        let config = Arc::new(config);
        let acceptor = TlsAcceptor::from(Arc::clone(&config));

        Ok(TrojanServer {
            acceptor,
            listener,
            passwords: self.sha224_passwords,
        })
    }
}

pub struct TrojanHandshaker {
    acceptor: TlsAcceptor,
    stream: TcpStream,
    passwords: Vec<String>,
}

impl ProxyHandshake for TrojanHandshaker {
    async fn handshake(self) -> IOResult<(impl ProxyConnection, (Addr, u16))> {
        let mut tls_stream = self.acceptor.accept(self.stream).await?;

        let req = TrojanRequst::receive_parse(&mut tls_stream).await?;

        let is_udp = req.cmd == CMD_UDP_ASSOCIATE;

        if !self.passwords.contains(&req.password) {
            return Err(Error::new(ErrorKind::PermissionDenied, "Invalid user"));
        }

        let trojan_client = TrojanClient {
            tls: tls_stream,
            dst: req.host.clone(),
            dst_port: req.port,
            connected: true,
            password: String::new(),
            is_udp,
        };

        Ok((trojan_client, (req.host, req.port)))
    }
}

/**
 * # Trojan server
 * Protocol details at <https://trojan-gfw.github.io/trojan/protocol>
 */
pub struct TrojanServer {
    acceptor: TlsAcceptor,
    listener: TcpListener,

    passwords: Vec<String>,
}

impl ProxyServer for TrojanServer {
    async fn accept(&mut self) -> IOResult<(impl ProxyHandshake, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;

        Ok((
            TrojanHandshaker {
                acceptor: self.acceptor.clone(),
                stream,
                passwords: self.passwords.clone(),
            },
            addr,
        ))
    }
}

/**
 * # Trojan client
 * Protocol details at <https://trojan-gfw.github.io/trojan/protocol>
 */
pub struct TrojanClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub dst: Addr,
    pub dst_port: u16,

    tls: T,
    connected: bool,
    password: String,
    is_udp: bool,
}

impl<T> ProxyConnection for TrojanClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        if self.is_udp {
            let mut read_buf1 = vec![0; UDP_MAX_PACK_SIZE];
            let mut read_buf = ReadBuf::new(&mut read_buf1);

            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut read_buf))?;

            let udp_pack = UdpPacket::parse_packet(read_buf.filled())?;

            let written_size = std::cmp::min(buf.capacity(), udp_pack.payload.len());
            buf.put_slice(&udp_pack.payload[..written_size]);
            Poll::Ready(Ok(Network::Udp((udp_pack.host, udp_pack.port))))
        } else {
            ready!(Pin::new(&mut self.tls).poll_read(cx, buf))?;
            Poll::Ready(Ok(Network::Tcp))
        }
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        network: Network,
    ) -> Poll<IOResult<usize>> {
        if !self.connected {
            match network {
                Network::Tcp => {
                    let req = TrojanRequst {
                        password: self.password.clone(),
                        host: self.dst.clone(),
                        port: self.dst_port,
                        cmd: CMD_CONNECT,
                    };
                    self.connected = true;
                    Pin::new(&mut self.tls).poll_write(cx, &req.build_packet(buf))
                }
                Network::Udp((host, port)) => {
                    let udp_pack = UdpPacket {
                        host,
                        port,
                        payload: buf.to_vec(),
                    };

                    let req = TrojanRequst {
                        password: self.password.clone(),
                        host: self.dst.clone(),
                        port: self.dst_port,
                        cmd: CMD_UDP_ASSOCIATE,
                    };
                    self.is_udp = true;
                    self.connected = true;
                    Pin::new(&mut self.tls)
                        .poll_write(cx, &req.build_packet(&udp_pack.build_packet()))
                }
            }
        } else {
            match network {
                Network::Tcp => Pin::new(&mut self.tls).poll_write(cx, buf),
                Network::Udp((host, port)) => {
                    let udp_pack = UdpPacket {
                        host,
                        port,
                        payload: buf.to_vec(),
                    };
                    Pin::new(&mut self.tls).poll_write(cx, &udp_pack.build_packet())
                }
            }
        }
    }
}
