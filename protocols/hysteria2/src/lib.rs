use bytes::{Buf, BufMut, BytesMut};
use common::{Network, ProxyConnection};
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::{Connection, OpenStreams};
use quinn::{
    RecvStream, SendStream,
    rustls::{ClientConfig, RootCertStore},
};
use quinn_proto::{VarInt, coding::Codec};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::ToSocketAddrs,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

const HYSTERIA_STATUS_OK: u16 = 233;

struct Hy2TcpCodec;

impl Encoder<&str> for Hy2TcpCodec {
    type Error = Error;
    fn encode(&mut self, item: &str, dst: &mut BytesMut) -> Result<(), Self::Error> {
        pub fn var_size(var: VarInt) -> usize {
            let x = var.into_inner();
            if x < 2u64.pow(6) {
                1
            } else if x < 2u64.pow(14) {
                2
            } else if x < 2u64.pow(30) {
                4
            } else if x < 2u64.pow(62) {
                8
            } else {
                unreachable!();
            }
        }
        pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
            use rand::Rng;
            use rand::distr::StandardUniform;

            let mut rng = rand::rng();
            let len = rng.random_range(range) as usize;
            rng.sample_iter(StandardUniform).take(len).collect()
        }
        const REQ_ID: VarInt = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        let addr = item.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        dst.reserve(
            var_size(REQ_ID)
                + var_size(padding_var)
                + var_size(addr_var)
                + addr.len()
                + padding.len(),
        );

        REQ_ID.encode(dst);

        addr_var.encode(dst);
        dst.put_slice(&addr);

        padding_var.encode(dst);
        dst.put_slice(&padding);

        Ok(())
    }
}

#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

impl Decoder for Hy2TcpCodec {
    type Error = Error;
    type Item = Hy2TcpResp;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining_mut() {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let status = src.get_u8();
        let msg_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::InvalidData)?
            .into_inner() as usize;

        if src.remaining_mut() < msg_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        let msg: Vec<u8> = src.split_to(msg_len).into();
        let msg: String =
            String::from_utf8(msg).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let padding_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::UnexpectedEof)?
            .into_inner() as usize;

        if src.remaining_mut() < padding_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        unsafe {
            src.advance_mut(padding_len);
        }

        Ok(Hy2TcpResp { status, msg }.into())
    }
}

#[derive(Default, Clone)]
pub struct Hysteria2Connector {
    sni: Option<String>,
    password: String,
    insecure: bool,
}

impl Hysteria2Connector {
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
    pub fn password<S>(mut self, password: S) -> Self
    where
        S: Into<String>,
    {
        self.password = password.into();
        self
    }
    pub fn sni<S>(mut self, sni: S) -> Self
    where
        S: Into<String>,
    {
        self.sni = Some(sni.into());
        self
    }
    pub async fn connect<A>(&self, server: A, dst_addr: &str) -> anyhow::Result<Hysteria2Client>
    where
        A: ToSocketAddrs,
    {
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();

        if self.insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(common::SkipServerVerification));
        }

        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));
        let mut client_endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);

        let sni = self.sni.clone().unwrap_or_default();

        let conn = client_endpoint
            .connect(server.to_socket_addrs()?.next().unwrap(), &sni)?
            .await?;

        let h3_conn = Connection::new(conn.clone());
        let (mut _driver, mut send_request) = h3::client::new(h3_conn).await?;

        let req = http::Request::builder()
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", "0")
            .method("POST")
            .body(())?;
        let mut stream = send_request.send_request(req).await?;

        /* finish on the sending side */
        stream.finish().await?;
        let resp = stream.recv_response().await?;

        if resp.status() != HYSTERIA_STATUS_OK {
            return Err(Error::new(ErrorKind::Other, "cannot authenticate").into());
        }

        let (mut stream_write, mut stream_read) = conn.open_bi().await?;

        FramedWrite::new(&mut stream_write, Hy2TcpCodec)
            .send(dst_addr)
            .await?;

        FramedRead::new(&mut stream_read, Hy2TcpCodec)
            .next()
            .await
            .unwrap()?;

        Ok(Hysteria2Client {
            stream_read,
            stream_write,
            _send_request: send_request,
        })
    }
}

pub struct Hysteria2Client {
    stream_read: RecvStream,
    stream_write: SendStream,
    /** `send_request` cannot be dropped */
    _send_request: SendRequest<OpenStreams, bytes::Bytes>,
}

impl ProxyConnection for Hysteria2Client {
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        let size = ready!(Pin::new(&mut self.stream_write).poll_write(cx, buf))?;
        Poll::Ready(Ok(size))
    }
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        ready!(Pin::new(&mut self.stream_read).poll_read(cx, buf))?;

        Poll::Ready(Ok(Network::Tcp))
    }
}
