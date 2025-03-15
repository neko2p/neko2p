use common::{Network, ProxyConnection};
use std::{
    io::Result as IOResult,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

pub struct DirectConnection {
    stream: TcpStream,
}

impl DirectConnection {
    pub async fn connect<A>(addr: A) -> IOResult<Self>
    where
        A: ToSocketAddrs,
    {
        Ok(Self {
            stream: TcpStream::connect(addr).await?,
        })
    }
}

impl ProxyConnection for DirectConnection {
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        ready!(Pin::new(&mut self.stream).poll_read(cx, buf))?;

        Poll::Ready(Ok(Network::Tcp))
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IOResult<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
