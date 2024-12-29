use common::{Network, ProxyConnection};
use std::io::Result as IOResult;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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
    async fn receive(&mut self, buf: &mut [u8]) -> IOResult<(usize, Network)> {
        Ok((self.stream.read(buf).await?, Network::Tcp))
    }
    async fn send(&mut self, buf: &[u8], _network: Network) -> IOResult<usize> {
        self.stream.write(buf).await
    }
}
