use common::{Addr, Network, ProxyConnection, BUF_SIZE};
use std::io::{Cursor, Error, ErrorKind, Result as IOResult};
use tokio::net::{TcpListener, TcpStream};

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
    pub dst_addr: Addr,
    pub dst_port: u16,
    pub src_addr: String,
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
    pub async fn accept(&mut self) -> IOResult<Socks5Client> {
        use tokio::io::AsyncWriteExt;

        let (mut client, addr) = self.listener.accept().await?;

        /* receive header and nmethods */
        read_tcp(&mut client).await?;

        client
            .write_all(&[VER, METHOD_NO_AUTHENTICATION_REQUIRED])
            .await?;

        let data = read_tcp(&mut client).await?;

        let req = Socks5Request::parse(&data)?;
        if req.cmd == CMD_CONNECT {
            client
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

        let socks5_client = Socks5Client {
            stream: client,
            dst_addr: req.addr,
            dst_port: req.port,
            src_addr: addr.to_string(),
        };

        Ok(socks5_client)
    }
}

impl ProxyConnection for Socks5Client {
    async fn receive(&mut self, buf: &mut [u8]) -> IOResult<(usize, common::Network)> {
        use tokio::io::AsyncReadExt;

        let size = self.stream.read(buf).await?;
        Ok((size, Network::Tcp))
    }
    async fn send(&mut self, buf: &[u8], _network: Network) -> IOResult<usize> {
        use tokio::io::AsyncWriteExt;

        self.stream.write(buf).await
    }
}
