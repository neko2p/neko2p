use common::{Addr, Network, ProxyConnection, ProxyServer};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

const VER: u8 = 5;
const RSV: u8 = 0;

const REP_SUCCESS: u8 = 0;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const CMD_CONNECT: u8 = 1;

const METHOD_NO_AUTHENTICATION_REQUIRED: u8 = 0;

#[derive(Default)]
struct Socks5Response {
    bind_port: u16,
    rep: u8,
}

impl Socks5Response {
    fn build(&self) -> Vec<u8> {
        let mut bytes = vec![VER, self.rep, RSV, ATYP_IPV4, 127, 0, 0, 1];

        bytes.extend(self.bind_port.to_be_bytes());

        bytes
    }
    async fn receive_parse(stream: &mut TcpStream) -> IOResult<Self> {
        let ver = stream.read_u8().await?;
        if ver != VER {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid socks5 version 0x{:02}", ver),
            ));
        }
        let rep = stream.read_u8().await?;
        stream.read_u8().await?; // RSV

        match stream.read_u8().await? {
            ATYP_IPV4 => {
                let mut ipv4_addr = [0_u8; 4];
                for i in &mut ipv4_addr {
                    *i = stream.read_u8().await?;
                }
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(stream.read_u8().await? as char);
                }
            }
            ATYP_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = stream.read_u16().await?;
                }
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid ATYP")),
        }

        let bind_port = stream.read_u16().await?;

        Ok(Self { rep, bind_port })
    }
}

/**
 * Datapack for socks5 METHOD selection message.
*/
#[derive(Debug)]
struct Socks5Handshake {
    methods: Vec<u8>,
}

impl Socks5Handshake {
    async fn receive_parse_nmethod(stream: &mut TcpStream) -> IOResult<Self> {
        let ver = stream.read_u8().await?;
        if ver != VER {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid socks5 version 0x{:02}", ver),
            ));
        }
        let nmethods = stream.read_u8().await? as usize;

        let mut methods = Vec::new();
        for _ in 0..nmethods {
            methods.push(stream.read_u8().await?);
        }

        Ok(Self { methods })
    }
    async fn receive_parse_select(stream: &mut TcpStream) -> IOResult<u8> {
        let ver = stream.read_u8().await?;
        if ver != VER {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid socks5 version 0x{:02}", ver),
            ));
        }

        let method = stream.read_u8().await?;

        Ok(method)
    }
}

/**
 * Datapack for socks5 resquest message.
*/
#[derive(Debug)]
struct Socks5Request {
    cmd: u8,
    addr: Addr,
    port: u16,
}

impl Socks5Request {
    fn build(self) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.push(VER);
        pack.push(self.cmd);
        pack.push(RSV);
        match self.addr {
            Addr::IPv4(ipv4) => {
                pack.push(ATYP_IPV4);
                pack.extend(ipv4)
            }
            Addr::IPv6(ipv6) => {
                pack.push(ATYP_IPV6);
                for u16num in ipv6 {
                    pack.extend(u16num.to_be_bytes());
                }
            }
            Addr::Domain(domain) => {
                pack.push(ATYP_DOMAIN);
                pack.push(domain.len() as u8);
                pack.extend(domain.as_bytes());
            }
        }
        pack.extend(self.port.to_be_bytes());

        pack
    }
    async fn receive_parse(stream: &mut TcpStream) -> IOResult<Self> {
        let ver = stream.read_u8().await?;
        if ver != VER {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid socks5 version 0x{:02}", ver),
            ));
        }
        let cmd = stream.read_u8().await?;
        stream.read_u8().await?; // RSV

        let addr;
        match stream.read_u8().await? {
            ATYP_IPV4 => {
                let mut ipv4_addr = [0_u8; 4];
                for i in &mut ipv4_addr {
                    *i = stream.read_u8().await?;
                }
                addr = Addr::IPv4(ipv4_addr);
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(stream.read_u8().await? as char);
                }
                addr = Addr::Domain(domain);
            }
            ATYP_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = stream.read_u16().await?;
                }
                addr = Addr::IPv6(ipv6);
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid ATYP")),
        }

        let port = stream.read_u16().await?;

        Ok(Self { cmd, addr, port })
    }
}

/** # Socks5 client
 * Protocol details at <https://datatracker.ietf.org/doc/html/rfc1928>
 */
pub struct Socks5Client {
    pub stream: TcpStream,
}

impl Socks5Client {
    /** Connect to a remote socks5 server */
    pub async fn connect<A>(addr: A, dst_addr: Addr, dst_port: u16) -> IOResult<Self>
    where
        A: ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(addr).await?;

        stream
            .write_all(&[VER, 1, METHOD_NO_AUTHENTICATION_REQUIRED])
            .await?;

        Socks5Handshake::receive_parse_select(&mut stream).await?;

        let req = Socks5Request {
            cmd: CMD_CONNECT,
            addr: dst_addr,
            port: dst_port,
        }
        .build();
        stream.write_all(&req).await?;

        Socks5Response::receive_parse(&mut stream).await?;

        Ok(Self { stream })
    }
}

/** # Socks5 server
 * Protocol details at <https://datatracker.ietf.org/doc/html/rfc1928>
 */
pub struct Socks5Server {
    bind_port: u16,
    listener: TcpListener,
}

impl Socks5Server {
    pub async fn listen(host: &str, port: u16) -> IOResult<Self> {
        let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;

        Ok(Self {
            listener,
            bind_port: port,
        })
    }
}

impl ProxyServer for Socks5Server {
    async fn accept(
        &self,
    ) -> IOResult<(
        impl ProxyConnection + Send + Unpin + 'static,
        (Addr, u16),
        SocketAddr,
    )> {
        use tokio::io::AsyncWriteExt;

        let (mut stream, addr) = self.listener.accept().await?;

        /* receive header and nmethods */
        let nmethods = Socks5Handshake::receive_parse_nmethod(&mut stream).await?;

        if !nmethods
            .methods
            .contains(&METHOD_NO_AUTHENTICATION_REQUIRED)
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "no supported method found",
            ));
        }
        stream
            .write_all(&[VER, METHOD_NO_AUTHENTICATION_REQUIRED])
            .await?;

        let req = Socks5Request::receive_parse(&mut stream).await?;
        if req.cmd == CMD_CONNECT {
            stream
                .write_all(
                    &Socks5Response {
                        bind_port: self.bind_port,
                        rep: REP_SUCCESS,
                    }
                    .build(),
                )
                .await?;
        } else {
            unimplemented!();
        }

        let socks5_client = Socks5Client { stream };

        Ok((socks5_client, (req.addr, req.port), addr))
    }
}

impl ProxyConnection for Socks5Client {
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>> {
        let mut read_buf = ReadBuf::new(buf);

        match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
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
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
}
