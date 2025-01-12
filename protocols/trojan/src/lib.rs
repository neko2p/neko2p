use common::{Addr, Network, ProxyConnection, SkipServerVerification};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::ToSocketAddrs,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore, ServerConfig},
    server::TlsStream as ServerTlsStream,
    TlsAcceptor, TlsConnector,
};

const CRLF: &[u8; 2] = b"\r\n";

const CMD_CONNECT: u8 = 1;

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
}

impl TrojanRequst {
    fn build(&self, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.password.as_bytes());
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
        bytes.extend(payload);

        bytes
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
        stream.read_u8().await?; // CMD

        let host;
        match stream.read_u8().await? {
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
            _ => unreachable!(),
        }

        let port = stream.read_u16().await?;
        stream.read_u16().await?; // CRLF

        Ok(Self {
            password,
            host,
            port,
        })
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
    pub async fn connect(
        self,
        host: &str,
        port: u16,
        dst: Addr,
        dst_port: u16,
    ) -> IOResult<TrojanClient<TlsStream<TcpStream>>> {
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
            password: self.sha224_password,
            dst,
            dst_port,
            connected: false,
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
        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok(TrojanServer {
            acceptor,
            listener,
            passwords: self.sha224_passwords,
        })
    }
}

/**
 * # Trojan server
 * Protocol details at <https://trojan-gfw.github.io/trojan/protocol>
 */
pub struct TrojanServer {
    acceptor: TlsAcceptor,
    listener: TcpListener,
    pub passwords: Vec<String>,
}

impl TrojanServer {
    pub async fn accept(
        &mut self,
    ) -> IOResult<(TrojanClient<ServerTlsStream<TcpStream>>, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let mut tls_stream = self.acceptor.accept(stream).await?;

        let req = TrojanRequst::receive_parse(&mut tls_stream).await?;

        if !self.passwords.contains(&req.password) {
            return Err(Error::new(ErrorKind::PermissionDenied, "Invalid user"));
        }

        let trojan_client = TrojanClient {
            tls: tls_stream,
            dst: req.host,
            dst_port: req.port,
            connected: true,
            password: String::new(),
        };

        Ok((trojan_client, addr))
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
}

impl<T> ProxyConnection for TrojanClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.tls).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => match result {
                Ok(_) => {
                    let size = read_buf.filled().len();
                    Poll::Ready(Ok((size, Network::Tcp)))
                }
                Err(err) => Poll::Ready(Err(err)),
            },
        }
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        if !self.connected {
            let req = TrojanRequst {
                password: self.password.clone(),
                host: self.dst.clone(),
                port: self.dst_port,
            };
            self.connected = true;
            Pin::new(&mut self.tls).poll_write(cx, &req.build(&buf))
        } else {
            Pin::new(&mut self.tls).poll_write(cx, buf)
        }
    }
}
