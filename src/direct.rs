use common::{Network, ProxyConnection};
use std::{
    io::Result as IOResult,
    pin::Pin,
    task::{Context, Poll},
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
        buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>> {
        let mut read_buf = ReadBuf::new(buf);

        match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(status) => match status {
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
