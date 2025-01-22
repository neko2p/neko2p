mod skip_cert_verify;
mod split;

use split::{ReadHalf, WriteHalf};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    io::Result as IOResult,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};

pub use crate::skip_cert_verify::SkipServerVerification;

pub const BUF_SIZE: usize = 4096;

#[derive(Clone, Debug)]
pub enum Addr {
    IPv4([u8; 4]),
    IPv6([u16; 8]),
    Domain(String),
}

impl Display for Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Addr::IPv4(addr) => write!(f, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])?,

            Addr::Domain(addr_str) => write!(f, "{}", addr_str)?,
            Addr::IPv6(addr) => write!(f, "{}", addr.map(|e| format!("{}", e)).to_vec().join(":"))?,
        }
        Ok(())
    }
}

impl FromStr for Addr {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpAddr::from_str(s) {
            Ok(ip_addr) => match ip_addr {
                IpAddr::V4(ipv4) => Ok(Addr::IPv4(ipv4.octets())),
                IpAddr::V6(ipv6) => Ok(Addr::IPv6(ipv6.segments())),
            },
            Err(_) => Ok(Addr::Domain(s.to_owned())),
        }
    }
}

impl Addr {
    pub fn to_socket_addr(&self, port: u16) -> String {
        match self {
            Self::IPv4(_) | Self::Domain(_) => format!("{}:{}", self, port),
            Self::IPv6(_) => format!("[{}]:{}", self, port),
        }
    }
}

#[derive(Clone)]
pub enum Network {
    Tcp,
    Udp((Addr, u16)),
}

pub trait ProxyServer {
    /** Accept a connection. */
    fn accept(
        &self,
    ) -> impl Future<
        Output = IOResult<(
            impl ProxyConnection + Send + Unpin + 'static,
            (Addr, u16),
            SocketAddr,
        )>,
    >;
}

pub struct Read<'a, T> {
    conn: &'a mut T,
    buf: &'a mut [u8],
}

impl<T> Future for Read<'_, T>
where
    T: ProxyConnection + Unpin,
{
    type Output = IOResult<(usize, Network)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = vec![0; self.buf.len()];
        let poll_result = ready!(Pin::new(&mut *self.conn).poll_receive(cx, &mut buf));

        self.buf.copy_from_slice(&buf);
        Poll::Ready(poll_result)
    }
}

pub struct Write<'a, T> {
    conn: &'a mut T,
    buf: &'a [u8],
    network: Network,
}

impl<T> Future for Write<'_, T>
where
    T: ProxyConnection + Unpin,
{
    type Output = IOResult<usize>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let network = self.network.clone();
        let buf = self.buf;
        Pin::new(&mut *self.conn).poll_send(cx, buf, network)
    }
}

pub trait ProxyConnection: Sized {
    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        network: Network,
    ) -> Poll<IOResult<usize>>;
    fn poll_receive(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>>;
    /**
     * Split a connection into `ReadHalf` and `WriteHalf`
     */
    fn split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        let inner = Arc::new(Mutex::new(self));
        (
            ReadHalf {
                inner: Arc::clone(&inner),
            },
            WriteHalf {
                inner: Arc::clone(&inner),
            },
        )
    }
    fn receive<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, Self> {
        Read { conn: self, buf }
    }
    fn send<'a>(&'a mut self, buf: &'a [u8], network: Network) -> Write<'a, Self> {
        Write {
            conn: self,
            buf,
            network,
        }
    }
}
