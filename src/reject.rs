use common::{Network, ProxyConnection};
use std::io::Result as IOResult;

#[derive(Default)]
pub struct DirectConnection {}

impl ProxyConnection for DirectConnection {
    async fn receive(&mut self, _buf: &mut [u8]) -> IOResult<(usize, Network)> {
        Ok((0, Network::Tcp))
    }
    async fn send(&mut self, _buf: &[u8], _network: Network) -> IOResult<usize> {
        Ok(0)
    }
}
