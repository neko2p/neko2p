use common::{Network, ProxyConnection};
use std::{
    io::Result as IOResult,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Default)]
pub struct DirectConnection {}

impl ProxyConnection for DirectConnection {
    fn poll_receive(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>> {
        Poll::Ready(Ok((0, Network::Tcp)))
    }
    fn poll_send(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        Poll::Ready(Ok(0))
    }
}
