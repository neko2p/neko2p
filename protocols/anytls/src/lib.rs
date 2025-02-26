mod padding_scheme;

use bytes::{Buf, BufMut};
use common::{Addr, Network, ProxyConnection, SkipServerVerification};
use padding_scheme::{DEFAULT_PADDING_SCHEME, PaddingScheme, SchemeToken};
use rustls_pki_types::ServerName;
use std::{
    io::Result as IOResult,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const FRAME_HEADER_LEN: usize = 1 + 4 + 2;

async fn send_frames<T>(
    frames: &[Frame],
    conn: &mut T,
    padding_scheme: &[SchemeToken],
) -> IOResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut padding_scheme = padding_scheme.iter();
    let mut data = Vec::new();
    for frame in frames {
        data.put_slice(&frame.build_packet());
    }

    match padding_scheme.next() {
        Some(SchemeToken::Range { min, max }) => {
            if data.len() < *min {
                let frame_waste = Frame::gen_padding(*min, *max);
                data.put_slice(&frame_waste.build_packet());
            }
            conn.write_all(&data).await?;
        }
        Some(SchemeToken::Check) => {}
        None => {}
    }

    Ok(())
}

/**
 * Datapack for anytls authorization message.
 */
#[derive(Debug)]
struct AuthorizationPacket {
    password: [u8; 32],
    padding_len: usize,
}

impl AuthorizationPacket {
    fn new(password: [u8; 32], min: usize, max: usize) -> Self {
        const HEADER_LEN: usize = 32 + 2;
        let padding_len = if min < HEADER_LEN {
            0
        } else {
            rand::random_range(min - HEADER_LEN..max - HEADER_LEN)
        };

        Self {
            password,
            padding_len,
        }
    }
    fn build_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.put_slice(&self.password);

        packet.put_u16(self.padding_len as u16);
        for _ in 0..self.padding_len {
            packet.put_u8(0);
        }

        packet
    }
}

fn to_socket_addr(addr: Addr, port: u16) -> Vec<u8> {
    let mut socket_addr = Vec::new();
    match addr {
        Addr::IPv4(ipv4) => {
            socket_addr.put_u8(ATYP_IPV4);
            socket_addr.put_slice(&ipv4);
        }
        Addr::IPv6(ipv6) => {
            socket_addr.put_u8(ATYP_IPV6);
            for seg in ipv6 {
                socket_addr.put_u16(seg);
            }
        }
        Addr::Domain(domain) => {
            socket_addr.put_u8(ATYP_DOMAIN);
            socket_addr.put_u8(domain.len() as u8);
            socket_addr.put_slice(domain.as_bytes());
        }
    }
    socket_addr.put_u16(port);

    socket_addr
}

/**
 * Datapack for anytls frame.
 */
#[derive(Debug)]
enum Frame {
    Syn { stream_id: u32 },
    Psh { stream_id: u32, payload: Vec<u8> },
    Fin { stream_id: u32 },
    Waste { stream_id: u32, padding_len: usize },
    Settings { stream_id: u32, scheme: Vec<u8> },
}

impl Frame {
    fn gen_padding(min: usize, max: usize) -> Self {
        let padding_len = rand::random_range(min - FRAME_HEADER_LEN..max - FRAME_HEADER_LEN);
        Self::Waste {
            stream_id: 0,
            padding_len,
        }
    }
    fn build_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        match self {
            Frame::Syn { stream_id } => {
                packet.put_u8(CMD_SYN);
                packet.put_u32(*stream_id);
                packet.put_u16(0);
            }
            Frame::Psh { stream_id, payload } => {
                packet.put_u8(CMD_PSH);
                packet.put_u32(*stream_id);
                packet.put_u16(payload.len() as u16);
                packet.put_slice(payload);
            }
            Frame::Fin { stream_id } => {
                packet.put_u8(CMD_FIN);
                packet.put_u32(*stream_id);
                packet.put_u16(0);
            }
            Frame::Waste {
                stream_id,
                padding_len,
            } => {
                packet.put_u8(CMD_WASTE);
                packet.put_u32(*stream_id);
                packet.put_u16(*padding_len as u16);
                for _ in 0..*padding_len {
                    packet.put_u8(0);
                }
            }
            Frame::Settings { stream_id, scheme } => {
                packet.put_u8(CMD_SETTINGS);
                packet.put_u32(*stream_id);
                packet.put_u16(scheme.len() as u16);
                packet.put_slice(scheme);
            }
        }

        packet
    }
    fn parse_packet(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FRAME_HEADER_LEN {
            return None;
        }

        let command = bytes.get_u8();
        let stream_id = bytes.get_u32();

        match command {
            CMD_PSH => {
                let len = bytes.get_u16();

                if bytes.len() >= len as usize {
                    Some(Self::Psh {
                        stream_id,
                        payload: bytes[..len as usize].to_owned(),
                    })
                } else {
                    None
                }
            }
            CMD_FIN => Some(Self::Fin { stream_id }),
            _ => unimplemented!(),
        }
    }
}

#[derive(Default)]
pub struct AnytlsConnector {
    sni: Option<String>,
    insecure: bool,
    sha256_password: [u8; 32],
}

impl AnytlsConnector {
    pub fn sni<S>(mut self, sni: S) -> Self
    where
        S: Into<String>,
    {
        self.sni = Some(sni.into());
        self
    }
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
    pub fn password<S>(mut self, password: S) -> Self
    where
        S: AsRef<[u8]>,
    {
        use sha2::{Digest, Sha256};

        self.sha256_password = Sha256::digest(password.as_ref()).into();
        self
    }
    pub async fn connect<A>(
        self,
        addr: A,
        dst: Addr,
        dst_port: u16,
    ) -> IOResult<impl ProxyConnection>
    where
        A: ToSocketAddrs,
    {
        let sock = TcpStream::connect(addr).await?;

        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();

        if self.insecure {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
        }

        let sni = self.sni.unwrap_or_default();

        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from(sni).unwrap();
        let mut tls = connector.connect(domain, sock).await?;

        let mut padding_scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME);

        if let SchemeToken::Range { min, max } = padding_scheme.next().unwrap().first().unwrap() {
            tls.write_all(
                &AuthorizationPacket::new(self.sha256_password, *min, *max).build_packet(),
            )
            .await?;

            let mut padding_md5 = String::new();
            for i in md5::compute(DEFAULT_PADDING_SCHEME).iter() {
                padding_md5.push_str(&format!("{:02x}", i));
            }
            let frame_setting = Frame::Settings {
                stream_id: 0,
                scheme: format!(
                    "v=1
client=neko2p/0.1.0
padding-md5={}",
                    padding_md5
                )
                .as_bytes()
                .to_vec(),
            };

            let stream_id = rand::random();
            let frame_syn = Frame::Syn { stream_id };
            let frame_psh = Frame::Psh {
                stream_id,
                payload: to_socket_addr(dst, dst_port),
            };

            send_frames(
                &[frame_setting, frame_syn, frame_psh],
                &mut tls,
                &padding_scheme.next().unwrap(),
            )
            .await?;

            Ok(AnytlsClient {
                tls,
                stream_id,
                padding_scheme,

                read_buf: Vec::default(),
                data_remain: Vec::default(),
                split_packets: Vec::default(),
            })
        } else {
            unimplemented!()
        }
    }
}

/**
 * # anytls client
 * Protocol details at <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>
 */
pub struct AnytlsClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    tls: T,
    stream_id: u32,
    padding_scheme: PaddingScheme,

    read_buf: Vec<u8>,
    data_remain: Vec<u8>,
    split_packets: Vec<Vec<u8>>,
}

impl<T> AnytlsClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn split_packet(&mut self, mut data: &[u8], stream_id: u32, padding_schemes: &[SchemeToken]) {
        for token in padding_schemes {
            match token {
                SchemeToken::Range { min, max } => {
                    if data.is_empty() {
                        let mut split_packet = Vec::new();
                        let frame_waste = Frame::gen_padding(*min, *max);

                        split_packet.put_slice(&frame_waste.build_packet());
                        self.split_packets.push(split_packet);
                    } else if data.len() + FRAME_HEADER_LEN < *min {
                        let mut split_packet = Vec::new();
                        let frame_waste = Frame::gen_padding(
                            *min - (data.len() + FRAME_HEADER_LEN),
                            *max - (data.len() + FRAME_HEADER_LEN),
                        );

                        split_packet.put_slice(
                            &Frame::Psh {
                                stream_id,
                                payload: data.to_vec(),
                            }
                            .build_packet(),
                        );
                        data = &[];

                        split_packet.put_slice(&frame_waste.build_packet());
                        self.split_packets.push(split_packet);

                        break;
                    } else if data.len() + FRAME_HEADER_LEN > *max {
                        self.split_packets.push(
                            Frame::Psh {
                                stream_id,
                                payload: data[..max - FRAME_HEADER_LEN].to_vec(),
                            }
                            .build_packet(),
                        );

                        data = &data[max - FRAME_HEADER_LEN..];
                    }
                }
                SchemeToken::Check => {
                    if data.is_empty() {
                        break;
                    }
                }
            }
        }

        if !data.is_empty() {
            self.split_packets.push(
                Frame::Psh {
                    stream_id,
                    payload: data.to_vec(),
                }
                .build_packet(),
            );
        }
    }
}

impl<T> ProxyConnection for AnytlsClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        if !self.data_remain.is_empty() {
            let written_size = std::cmp::min(buf.capacity(), self.data_remain.len());
            buf.put_slice(&self.data_remain[..written_size]);
            self.data_remain.drain(..written_size);
            return Poll::Ready(Ok(Network::Tcp));
        }

        while Frame::parse_packet(&self.read_buf).is_none() {
            ready!(Pin::new(&mut self.tls).poll_read(cx, buf))?;
            self.read_buf.extend(buf.filled());
            buf.clear();
        }

        let frame = Frame::parse_packet(&self.read_buf);
        match frame {
            Some(Frame::Psh { payload, .. }) => {
                let written_size = std::cmp::min(buf.capacity(), payload.len());
                buf.put_slice(&payload[..written_size]);
                self.data_remain.extend(&payload[written_size..]);
                self.read_buf.drain(..payload.len() + FRAME_HEADER_LEN);
                Poll::Ready(Ok(Network::Tcp))
            }
            Some(Frame::Fin { .. }) => Poll::Ready(Ok(Network::Tcp)),
            _ => unimplemented!(),
        }
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        while !self.split_packets.is_empty() {
            let packet = self.split_packets.first().unwrap().clone();
            ready!(Pin::new(&mut self.tls).poll_write(cx, &packet))?;
            self.split_packets.remove(0);
        }

        let stream_id = self.stream_id;

        match self.padding_scheme.next() {
            Some(padding_scheme) => {
                self.split_packet(buf, stream_id, &padding_scheme);

                while !self.split_packets.is_empty() {
                    let packet = self.split_packets.first().unwrap().clone();
                    ready!(Pin::new(&mut self.tls).poll_write(cx, &packet))?;
                    self.split_packets.remove(0);
                }
                Poll::Ready(Ok(buf.len()))
            }
            None => {
                let frame_psh = Frame::Psh {
                    stream_id,
                    payload: buf.to_vec(),
                };
                Pin::new(&mut self.tls).poll_write(cx, &frame_psh.build_packet())
            }
        }
    }
}
