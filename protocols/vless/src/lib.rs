use common::{Addr, Network, ProxyConnection, BUF_SIZE};
use std::io::Result as IOResult;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};

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
}

#[derive(Default)]
pub struct VlessConnector {
    uuid: uuid::Uuid,
}

impl VlessConnector {
    pub fn uuid(mut self, uuid: uuid::Uuid) -> Self {
        self.uuid = uuid;

        self
    }
    pub async fn connect<A>(self, addr: A, dst: Addr, dst_port: u16) -> IOResult<VlessClient>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;

        Ok(VlessClient {
            stream,
            uuid: self.uuid,
            dst,
            dst_port,

            is_first_send: true,
            is_first_recv: true,
        })
    }
}

/** # VLESS client
 * Protocol details at <https://xtls.github.io/development/protocols/vless.html>
 */
pub struct VlessClient {
    stream: TcpStream,
    uuid: uuid::Uuid,
    dst: Addr,
    dst_port: u16,

    is_first_send: bool,
    is_first_recv: bool,
}

impl VlessClient {
    fn build_request(&self, payload: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();

        pack.push(VLESS_VERSION);
        pack.extend(self.uuid.as_bytes());
        pack.push(0); // no additional information
        pack.push(CMD_TCP);
        pack.extend(self.dst_port.to_be_bytes());
        match &self.dst {
            Addr::IPv4(ipv4) => {
                pack.push(ADDR_IPV4);
                pack.extend(ipv4);
            }
            Addr::Domain(domain) => {
                pack.push(ADDR_DOMAIN);
                pack.push(domain.len() as u8);
                pack.extend(domain.as_bytes());
            }
            Addr::IPv6(ipv6) => {
                pack.push(ADDR_IPV6);
                for seg in ipv6 {
                    pack.extend(seg.to_be_bytes());
                }
            }
        }
        pack.extend(payload);

        pack
    }
}

impl ProxyConnection for VlessClient {
    async fn receive(&mut self, buf: &mut [u8]) -> IOResult<(usize, Network)> {
        if self.is_first_recv {
            let mut recv_buf = vec![0; BUF_SIZE];
            let size = self.stream.read(&mut recv_buf).await?;

            let res = VlessResponse::parse(&recv_buf[..size]);
            buf[..res.payload.len()].copy_from_slice(&res.payload);
            self.is_first_recv = false;
            Ok((res.payload.len(), Network::Tcp))
        } else {
            let size = self.stream.read(buf).await?;
            Ok((size, Network::Tcp))
        }
    }
    async fn send(&mut self, buf: &[u8], _network: Network) -> IOResult<usize> {
        if self.is_first_send {
            self.is_first_recv = false;
            self.stream.write(&self.build_request(buf)).await
        } else {
            self.stream.write(buf).await
        }
    }
}
