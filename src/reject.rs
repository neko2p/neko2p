use common::{Network, ProxyConnection};
use std::{
    io::Result as IOResult,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

#[derive(Default)]
pub struct DirectConnection {}

impl ProxyConnection for DirectConnection {
    fn poll_receive(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        Poll::Ready(Ok(Network::Tcp))
    }
    fn poll_send(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        Poll::Ready(Ok(0))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IOResult<()>> {
        Poll::Ready(Ok(()))
    }
}
