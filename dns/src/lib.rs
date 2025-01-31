use bytes::BufMut;
use common::{
    utils::{to_sock_addr, Buf},
    Addr, Network, ProxyConnection,
};
use std::{
    io::Result as IOResult,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};
use tokio::net::UdpSocket;

const DNS_PORT: u16 = 53;

const DNS_FLAG_RECURSION: u16 = 1 << 8;

const QUERY_TYPE_A: u16 = 1;
const QUERY_CLASS: u16 = 1;

const UDP_MAX_PACK_SIZE: usize = 65535;

async fn read_udp(sock: &UdpSocket) -> IOResult<Vec<u8>> {
    let mut buf = vec![0; UDP_MAX_PACK_SIZE];
    let (size, _) = sock.recv_from(&mut buf).await?;
    buf.drain(size..);

    Ok(buf)
}

#[derive(Default, Debug)]
struct DNSPack {
    trans_id: u16,
    flags: u16,
    domain: String,
    ips: Vec<IpAddr>,
}

impl DNSPack {
    fn new() -> Self {
        Self {
            trans_id: rand::random(),
            flags: DNS_FLAG_RECURSION,
            ..Default::default()
        }
    }
    fn parse_packet(mut bytes: &[u8]) -> IOResult<Self> {
        let trans_id = bytes.get_u16()?;
        let flags = bytes.get_u16()?;
        bytes.get_u16()?;
        bytes.get_u16()?;
        bytes.get_u16()?;
        bytes.get_u16()?;

        let mut domain: Vec<String> = Vec::new();
        loop {
            let len = bytes.get_u8()?;
            if len == 0 {
                break;
            }
            let mut seg = String::new();
            for _ in 0..len {
                seg.push(bytes.get_u8()? as char);
            }
            domain.push(seg);
        }
        bytes.get_u16()?; // query type
        bytes.get_u16()?; // class type

        bytes.get_u16()?; // domain pointer
        bytes.get_u16()?; // query type
        bytes.get_u16()?; // class type
        bytes.get_u32()?; // ttl
        bytes.get_u16()?; // data len

        let ip = Ipv4Addr::from_bits(bytes.get_u32()?);

        Ok(Self {
            trans_id,
            flags,
            domain: domain.join("."),
            ips: vec![IpAddr::V4(ip)],
        })
    }
    fn build_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.put_u16(self.trans_id);
        packet.put_u16(self.flags);
        packet.put_u16(1);
        packet.put_u16(0);
        packet.put_u16(0);
        packet.put_u16(0);
        for seg in self.domain.split('.') {
            packet.put_u8(seg.len() as u8);
            packet.put_slice(seg.as_bytes());
        }
        packet.put_u8(0);
        packet.put_u16(QUERY_TYPE_A);
        packet.put_u16(QUERY_CLASS);

        packet
    }
}

enum Nameserver {
    Dns(String),
}

pub struct DNSResolver {
    nameserver: Nameserver,
}

impl DNSResolver {
    pub fn new_dns(nameserver: &str) -> Self {
        Self {
            nameserver: Nameserver::Dns(nameserver.to_owned()),
        }
    }
    pub async fn query(&self, domain: &str) -> IOResult<IpAddr> {
        match &self.nameserver {
            Nameserver::Dns(server) => {
                let mut pack = DNSPack::new();
                pack.domain = domain.to_owned();
                let sock = UdpSocket::bind("0.0.0.0:0").await?;
                sock.send_to(&pack.build_packet(), to_sock_addr(server, DNS_PORT))
                    .await?;
                let pack = DNSPack::parse_packet(&read_udp(&sock).await?)?;

                Ok(pack.ips[0])
            }
        }
    }
    pub async fn query_over_proxy<P>(&self, mut conn: P, domain: &str) -> IOResult<IpAddr>
    where
        P: ProxyConnection + Unpin,
    {
        match &self.nameserver {
            Nameserver::Dns(server) => {
                let mut pack = DNSPack::new();
                pack.domain = domain.to_owned();

                conn.send(
                    &pack.build_packet(),
                    Network::Udp((Addr::from_str(server).unwrap(), DNS_PORT)),
                )
                .await?;
                let mut buf = vec![0; UDP_MAX_PACK_SIZE];
                let (size, _) = conn.receive(&mut buf).await?;
                let pack = DNSPack::parse_packet(&buf[..size])?;

                Ok(pack.ips[0])
            }
        }
    }
}
