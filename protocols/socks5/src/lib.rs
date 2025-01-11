use common::{Addr, Network, ProxyConnection, BUF_SIZE};
use std::{
    io::{Cursor, Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
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

async fn read_tcp(sock: &mut TcpStream) -> IOResult<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut data = Vec::new();

    loop {
        let mut buf = [0; BUF_SIZE];

        let size = sock.read(&mut buf).await?;
        data.extend(&buf[..size]);
        if size < BUF_SIZE {
            return Ok(data);
        }
    }
}

#[derive(Default)]
struct Socks5Response {
    bind_port: u16,
}

impl Socks5Response {
    fn build(&self) -> Vec<u8> {
        let mut bytes = vec![VER, REP_SUCCESS, RSV, ATYP_IPV4, 127, 0, 0, 1];

        bytes.extend(self.bind_port.to_be_bytes());

        bytes
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
    fn parse(bytes: &[u8]) -> IOResult<Self> {
        use std::io::Read;
        let mut reader = Cursor::new(bytes);
        reader.set_position(3);
        let mut atyp = [0_u8; 1];
        reader.read_exact(&mut atyp)?;

        let addr;
        match atyp[0] {
            ATYP_IPV4 => {
                let mut ipv4_addr = [0_u8; 4];
                reader.read_exact(&mut ipv4_addr)?;
                addr = Addr::IPv4(ipv4_addr);
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0_u8; 1];
                reader.read_exact(&mut len_buf)?;

                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0_u8; len];
                reader.read_exact(&mut domain_buf)?;
                addr = Addr::Domain(String::from_utf8_lossy(&domain_buf).to_string());
            }
            ATYP_IPV6 => {
                if bytes.len() < 10 {
                    return Err(Error::new(ErrorKind::InvalidData, "Incomplete request"));
                }
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    let mut u16_buf = [0_u8; 2];
                    reader.read_exact(&mut u16_buf)?;
                    *i = u16::from_be_bytes(u16_buf);
                }
                addr = Addr::IPv6(ipv6);
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid ATYP")),
        }

        let mut port_buf = [0_u8; 2];
        reader.read_exact(&mut port_buf)?;
        let port = u16::from_be_bytes(port_buf);

        Ok(Self {
            cmd: bytes[1],
            addr,
            port,
        })
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

        read_tcp(&mut stream).await?;

        let req = Socks5Request {
            cmd: CMD_CONNECT,
            addr: dst_addr,
            port: dst_port,
        }
        .build();
        stream.write_all(&req).await?;

        read_tcp(&mut stream).await?;

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
    pub async fn accept(&mut self) -> IOResult<(Socks5Client, (Addr, u16), SocketAddr)> {
        use tokio::io::AsyncWriteExt;

        let (mut stream, addr) = self.listener.accept().await?;

        /* receive header and nmethods */
        read_tcp(&mut stream).await?;

        stream
            .write_all(&[VER, METHOD_NO_AUTHENTICATION_REQUIRED])
            .await?;

        let data = read_tcp(&mut stream).await?;

        let req = Socks5Request::parse(&data)?;
        if req.cmd == CMD_CONNECT {
            stream
                .write_all(
                    &Socks5Response {
                        bind_port: self.bind_port,
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
