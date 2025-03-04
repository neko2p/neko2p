use common::{Addr, Keepalive, Network, ProxyConnection};
use russh::{
    Channel,
    client::{Config, Handle, Handler, Msg, connect},
    keys::{PrivateKeyWithHashAlg, ssh_key::PublicKey},
};
use std::{
    io::{Error, ErrorKind, Result as IOResult},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::ToSocketAddrs,
};

struct ClientHandler {}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub enum Authorization {
    Password {
        username: String,
        password: String,
    },
    PrivateKey {
        username: String,
        key: String,
        passphrase: Option<String>,
    },
}

pub struct SshKeepalive {
    session: Handle<ClientHandler>,
}

pub struct SshConnection {
    channel: Channel<Msg>,
}

impl SshKeepalive {
    pub async fn connect<A>(addr: A, auth: Authorization) -> anyhow::Result<Self>
    where
        A: ToSocketAddrs,
    {
        let config = Arc::new(Config::default());
        let mut session = connect(config, addr, ClientHandler {}).await?;

        match auth {
            Authorization::Password { username, password } => {
                session.authenticate_password(username, password).await?;
            }
            Authorization::PrivateKey {
                username,
                key,
                passphrase,
            } => {
                let key = match passphrase {
                    Some(passphrase) => russh::keys::decode_secret_key(&key, Some(&passphrase))?,
                    None => russh::keys::decode_secret_key(&key, None)?,
                };
                let key = PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session.best_supported_rsa_hash().await?.flatten(),
                );
                session.authenticate_publickey(username, key).await?;
            }
        }

        Ok(Self { session })
    }
}

impl Keepalive for SshKeepalive {
    async fn connect(&self, dst: Addr, dst_port: u16) -> IOResult<impl ProxyConnection + 'static> {
        let channel = self
            .session
            .channel_open_direct_tcpip(dst.to_string(), dst_port as u32, "127.0.0.1", 5000)
            .await
            .map_err(|err| Error::new(ErrorKind::Other, format!("{:?}", err)))?;

        Ok(SshConnection { channel })
    }
}

impl ProxyConnection for SshConnection {
    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        Pin::new(&mut self.channel.make_writer()).poll_write(cx, buf)
    }
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<common::Network>> {
        ready!(Pin::new(&mut self.channel.make_reader()).poll_read(cx, buf))?;
        Poll::Ready(Ok(Network::Tcp))
    }
}
