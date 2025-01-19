mod skip_cert_verify;

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    io::Result as IOResult,
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
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

impl Addr {
    pub fn to_socket_addr(&self, port: u16) -> String {
        match self {
            Self::IPv4(_) | Self::Domain(_) => format!("{}:{}", self, port),
            Self::IPv6(_) => format!("[{}]:{}", self, port),
        }
    }
}

pub struct ReadHalf<T>
where
    T: ProxyConnection,
{
    inner: Arc<Mutex<T>>,
}

impl<T> ReadHalf<T>
where
    T: ProxyConnection,
{
    pub fn receive<'a>(&self, buf: &'a mut [u8]) -> Read<'a, T> {
        Read {
            inner: Arc::clone(&self.inner),
            buf,
        }
    }
}

pub struct Read<'a, T>
where
    T: ProxyConnection,
{
    inner: Arc<Mutex<T>>,
    buf: &'a mut [u8],
}

impl<T> Future for Read<'_, T>
where
    T: ProxyConnection + Unpin,
{
    type Output = IOResult<(usize, Network)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let poll_result;
        let mut buf = vec![0; self.buf.len()];
        {
            let mut stream_m = self.inner.lock().unwrap();
            let stream = Pin::new(stream_m.deref_mut());

            match stream.poll_receive(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => poll_result = result,
            }
        }
        self.buf.copy_from_slice(&buf);
        Poll::Ready(poll_result)
    }
}

pub struct WriteHalf<T> {
    inner: Arc<Mutex<T>>,
}

impl<T> WriteHalf<T>
where
    T: ProxyConnection,
{
    pub fn send<'a>(&self, buf: &'a [u8], network: Network) -> Write<'a, T> {
        Write {
            inner: Arc::clone(&self.inner),
            buf,
            network,
        }
    }
}

pub struct Write<'a, T>
where
    T: ProxyConnection,
{
    inner: Arc<Mutex<T>>,
    buf: &'a [u8],
    network: Network,
}

impl<T> Future for Write<'_, T>
where
    T: ProxyConnection + Unpin,
{
    type Output = IOResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut stream_m = self.inner.lock().unwrap();
        let stream = Pin::new(stream_m.deref_mut());
        stream.poll_send(cx, self.buf, self.network.clone())
    }
}

#[derive(Clone)]
pub enum Network {
    Tcp,
    Udp(Addr),
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
}
