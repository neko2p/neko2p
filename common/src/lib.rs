mod skip_cert_verify;

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    future::Future,
    io::Result as IOResult,
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
    T: ProxyConnection,
{
    type Output = IOResult<(usize, Network)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = vec![0; self.buf.len()];

        let mut read_size = None;
        let poll_status;

        {
            let mut stream = self.inner.lock().unwrap();
            let f = stream.receive(&mut buf);
            pin_utils::pin_mut!(f);
            poll_status = Pin::new(&mut f).poll(cx);
            if let Poll::Ready(Ok((size, _))) = &poll_status {
                read_size = Some(*size);
            }
        }

        if let Some(size) = read_size {
            self.buf[..size].copy_from_slice(&buf[..size]);
        }
        poll_status
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
    T: ProxyConnection,
{
    type Output = IOResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut stream = self.inner.lock().unwrap();
        let f = stream.send(self.buf, self.network);
        pin_utils::pin_mut!(f);
        Pin::new(&mut f).poll(cx)
    }
}

#[derive(Clone, Copy)]
pub enum Network {
    Tcp,
    Udp,
}

pub trait ProxyConnection: Sized {
    fn send(&mut self, buf: &[u8], network: Network) -> impl Future<Output = IOResult<usize>>;
    fn receive(&mut self, buf: &mut [u8]) -> impl Future<Output = IOResult<(usize, Network)>>;
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
