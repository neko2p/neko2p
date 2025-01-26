use bytes::BufMut;
use common::{Addr, Network, ProxyConnection, ProxyHandshake, ProxyServer, BUF_SIZE};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use uuid::Uuid;

const VLESS_VERSION: u8 = 0;
const CMD_TCP: u8 = 0x1;
const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 2;
const ADDR_IPV6: u8 = 3;

struct VlessResponse {
    payload: Vec<u8>,
}

impl VlessResponse {
    fn parse(buf: &[u8]) -> Self {
        let len = buf[1] as usize;
        let payload = buf[2 + len..].to_vec();

        Self { payload }
    }
    fn build(&self) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.put_u8(VLESS_VERSION);
        pack.put_u8(0);
        pack.put_slice(&self.payload);

        pack
    }
}

#[derive(Default)]
pub struct VlessServerBuilder {
    uuids: Vec<Uuid>,
}

impl VlessServerBuilder {
    pub fn add_uuid(mut self, uuid: Uuid) -> Self {
        self.uuids.push(uuid);
        self
    }
    pub async fn listen<A>(self, bind_addr: A) -> IOResult<VlessServer>
    where
        A: ToSocketAddrs,
    {
        let listener = TcpListener::bind(bind_addr).await?;

        Ok(VlessServer {
            listener,
            uuids: self.uuids,
        })
    }
}

pub struct VlessHandshaker {
    stream: TcpStream,
    uuids: Vec<Uuid>,
}

impl ProxyHandshake for VlessHandshaker {
    async fn handshake(mut self) -> IOResult<(impl ProxyConnection, (Addr, u16))> {
        /* receive header and nmethods */
        let req = VlessRequest::receive_parse(&mut self.stream).await?;

        /* check uuid validation */
        if !self.uuids.contains(&req.uuid) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("Invalid UUID: {}", req.uuid),
            ));
        }

        let socks5_client = VlessClient {
            stream: self.stream,
            uuid: req.uuid,
            dst: req.dst.clone(),
            dst_port: req.dst_port,

            inblound_connection: true,
            is_first_send: true,
            is_first_recv: true,
        };

        Ok((socks5_client, (req.dst, req.dst_port)))
    }
}

/** # VLESS server
 * Protocol details at <https://xtls.github.io/development/protocols/vless.html>
 */
pub struct VlessServer {
    listener: TcpListener,
    uuids: Vec<Uuid>,
}

impl ProxyServer for VlessServer {
    async fn accept(&self) -> IOResult<(impl ProxyHandshake, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;

        Ok((
            VlessHandshaker {
                stream,
                uuids: self.uuids.clone(),
            },
            addr,
        ))
    }
}

#[derive(Default)]
pub struct VlessConnector {
    uuid: Uuid,
}

impl VlessConnector {
    pub fn uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = uuid;

        self
    }
    pub async fn connect<T>(self, stream: T, dst: Addr, dst_port: u16) -> IOResult<VlessClient<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(VlessClient {
            stream,
            uuid: self.uuid,
            dst,
            dst_port,

            inblound_connection: false,
            is_first_send: true,
            is_first_recv: true,
        })
    }
}

/** # VLESS client
 * Protocol details at <https://xtls.github.io/development/protocols/vless.html>
 */
pub struct VlessClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream: T,
    uuid: Uuid,
    pub dst: Addr,
    pub dst_port: u16,

    inblound_connection: bool,
    is_first_send: bool,
    is_first_recv: bool,
}

struct VlessRequest {
    uuid: Uuid,
    dst: Addr,
    dst_port: u16,
}

impl VlessRequest {
    /** receive request header (no payload) and parse */
    async fn receive_parse(stream: &mut TcpStream) -> IOResult<Self> {
        let ver = stream.read_u8().await?;
        if ver != VLESS_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid VLESS version 0x{:02x}", ver),
            ));
        }

        let uuid = Uuid::from_u128(stream.read_u128().await?);
        if stream.read_u8().await? > 0 {
            unimplemented!();
        }
        stream.read_u8().await?;
        let dst_port = stream.read_u16().await?;

        let dst;
        match stream.read_u8().await? {
            ADDR_IPV4 => {
                let mut ipv4 = [0; 4];
                for i in &mut ipv4 {
                    *i = stream.read_u8().await?;
                }
                dst = Addr::IPv4(ipv4);
            }
            ADDR_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = stream.read_u16().await?;
                }
                dst = Addr::IPv6(ipv6);
            }
            ADDR_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(stream.read_u8().await? as char);
                }
                dst = Addr::Domain(domain);
            }
            _ => unreachable!(),
        }

        Ok(Self {
            uuid,
            dst,
            dst_port,
        })
    }
}

impl<T> VlessClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn build_request(&self, payload: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();

        pack.put_u8(VLESS_VERSION);
        pack.put_slice(self.uuid.as_bytes());
        pack.put_u8(0); // no additional information
        pack.put_u8(CMD_TCP);
        pack.put_u16(self.dst_port);
        match &self.dst {
            Addr::IPv4(ipv4) => {
                pack.put_u8(ADDR_IPV4);
                pack.put_slice(ipv4);
            }
            Addr::Domain(domain) => {
                pack.put_u8(ADDR_DOMAIN);
                pack.put_u8(domain.len() as u8);
                pack.put_slice(domain.as_bytes());
            }
            Addr::IPv6(ipv6) => {
                pack.put_u8(ADDR_IPV6);
                for seg in ipv6 {
                    pack.put_u16(*seg);
                }
            }
        }
        pack.put_slice(payload);

        pack
    }
}

impl<T> ProxyConnection for VlessClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        let mut read_buf1 = vec![0; BUF_SIZE];
        let mut read_buf = ReadBuf::new(&mut read_buf1);

        ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;

        if !self.inblound_connection && self.is_first_recv {
            let res = VlessResponse::parse(read_buf.filled());
            buf.put_slice(&res.payload);
            self.is_first_recv = false;
        } else {
            buf.put_slice(read_buf.filled());
        }
        Poll::Ready(Ok(Network::Tcp))
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        if self.is_first_send {
            self.is_first_send = false;

            if self.inblound_connection {
                let res = VlessResponse {
                    payload: buf.to_vec(),
                }
                .build();
                Pin::new(&mut self.stream).poll_write(cx, &res)
            } else {
                let req = self.build_request(buf);
                Pin::new(&mut self.stream).poll_write(cx, &req)
            }
        } else {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }
    }
}
