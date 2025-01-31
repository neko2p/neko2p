use common::{Addr, Network, ProxyConnection, ProxyHandshake, ProxyServer};
use futures::{FutureExt, SinkExt, StreamExt};
use lwip::{NetStack, TcpListener, TcpStream, UdpPkt, UdpSendHalf};
use std::{
    future::Future,
    io::Result as IOResult,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun::Configuration;

#[allow(dead_code)]
pub struct TunController {
    tcp_listener: TcpListener,
    udp_send: Arc<Mutex<UdpSendHalf>>,
    udp_packets: Arc<Mutex<Vec<UdpPkt>>>,
}

pub struct TunBuilder {
    address: IpAddr,
}

impl Default for TunBuilder {
    fn default() -> Self {
        Self {
            address: IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }
}

impl TunBuilder {
    pub fn address(mut self, address: &str) -> Self {
        self.address = IpAddr::from_str(address).unwrap();
        self
    }
    pub async fn create(self) -> IOResult<TunController> {
        let mut config = Configuration::default();
        config
            .address(self.address)
            .netmask((255, 255, 255, 0))
            .destination(self.address)
            .up();

        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });
        let device = tun::create_as_async(&config)?;

        let (stack, tcp_listener, udp_socket) = NetStack::new().unwrap();
        let (mut stack_sink, mut stack_stream) = stack.split();
        let (mut tun_sink, mut tun_stream) = device.into_framed().split();

        /* Reads packet from stack and sends to TUN. */
        tokio::spawn(async move {
            while let Some(Ok(pkt)) = stack_stream.next().await {
                tun_sink.send(pkt).await.unwrap();
            }
        });

        /* Reads packet from TUN and sends to stack. */
        tokio::spawn(async move {
            while let Some(Ok(pkt)) = tun_stream.next().await {
                stack_sink.send(pkt).await.unwrap();
            }
        });

        let (udp_send, mut udp_recv) = udp_socket.split();

        let udp_packets = Arc::new(Mutex::new(Vec::default()));

        let udp_packets2 = Arc::clone(&udp_packets);
        tokio::spawn(async move {
            while let Some(pkt) = udp_recv.next().await {
                udp_packets2.lock().unwrap().push(pkt);
            }
        });

        Ok(TunController {
            tcp_listener,
            udp_send: Arc::new(Mutex::new(udp_send)),
            udp_packets,
        })
    }
}

pub struct AcceptFuture<'a> {
    tcp_listener: &'a mut TcpListener,
    udp_send: Arc<Mutex<UdpSendHalf>>,
    udp_packets: Arc<Mutex<Vec<UdpPkt>>>,
}

impl Future for AcceptFuture<'_> {
    type Output = IOResult<(TunConnection, SocketAddr)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut fut = self.tcp_listener.next();
        if let Poll::Ready(Some((stream, local_addr, remote_addr))) = fut.poll_unpin(cx) {
            return Poll::Ready(Ok((
                TunConnection {
                    stream: Some(stream),
                    local_addr,
                    remote_addr,
                    udp_packets: Arc::clone(&self.udp_packets),
                    udp_send: Arc::clone(&self.udp_send),
                },
                local_addr,
            )));
        }
        /* a UDP packet is pending */
        if !self.udp_packets.lock().unwrap().is_empty() {
            let (_pkt, local_addr, remote_addr) =
                self.udp_packets.lock().unwrap().first().unwrap().clone();
            self.udp_packets.lock().unwrap().remove(0);

            return Poll::Ready(Ok((
                TunConnection {
                    stream: None,
                    local_addr,
                    remote_addr,
                    udp_packets: Arc::clone(&self.udp_packets),
                    udp_send: Arc::clone(&self.udp_send),
                },
                local_addr,
            )));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl ProxyServer for TunController {
    fn accept(&mut self) -> impl Future<Output = IOResult<(impl ProxyHandshake, SocketAddr)>> {
        AcceptFuture {
            tcp_listener: &mut self.tcp_listener,
            udp_send: Arc::clone(&self.udp_send),
            udp_packets: Arc::clone(&self.udp_packets),
        }
    }
}

pub struct TunConnection {
    stream: Option<TcpStream>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    udp_send: Arc<Mutex<UdpSendHalf>>,
    udp_packets: Arc<Mutex<Vec<UdpPkt>>>,
}

impl ProxyHandshake for TunConnection {
    async fn handshake(self) -> IOResult<(impl ProxyConnection, (Addr, u16))> {
        let addr = Addr::from_str(&self.remote_addr.ip().to_string()).unwrap();
        let port = self.remote_addr.port();
        Ok((self, (addr, port)))
    }
}

impl ProxyConnection for TunConnection {
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        network: Network,
    ) -> Poll<IOResult<usize>> {
        match &mut self.stream {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => match network {
                Network::Tcp => unreachable!(),
                Network::Udp((dst_addr, dst_port)) => {
                    let remote_addr =
                        SocketAddr::from_str(&dst_addr.to_socket_addr(dst_port)).unwrap();

                    self.udp_send
                        .lock()
                        .unwrap()
                        .send_to(buf, &remote_addr, &self.local_addr)?;
                    Poll::Ready(Ok(buf.len()))
                }
            },
        }
    }
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        match &mut self.stream {
            Some(stream) => {
                ready!(Pin::new(stream).poll_read(cx, buf))?;

                Poll::Ready(Ok(Network::Tcp))
            }
            None => {
                let packets = &mut self.udp_packets.lock().unwrap();
                for i in 0..packets.len() {
                    let (pkt, local_addr, remote_addr) = packets[i].clone();
                    if remote_addr == self.remote_addr && local_addr == self.local_addr {
                        packets.remove(i);
                        buf.put_slice(&pkt);

                        return Poll::Ready(Ok(Network::Udp((
                            Addr::from_str(&remote_addr.ip().to_string()).unwrap(),
                            remote_addr.port(),
                        ))));
                    }
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
