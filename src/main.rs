use clap::{Parser, Subcommand};
use common::{Addr, Keepalive, ProxyConnection, ProxyHandshake, ProxyServer, utils::to_sock_addr};
use config::{Inbound, Outbound, TLS_INSECURE_DEFAULT};
use hysteria2::Hysteria2Keepalive;
use route::Router;
use std::{
    any::Any, collections::HashMap, io::Result as IOResult, net::SocketAddr, path::Path,
    str::FromStr, sync::Arc,
};
use tokio::{sync::RwLock, task::JoinHandle};
use uuid::Uuid;

mod config;
mod direct;
mod reject;
mod route;
mod transport;

#[derive(Subcommand)]
enum Command {
    /** Run service */
    Run { config: String },
    /** Useful tools */
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand)]
enum ToolsCommand {
    /** Generate a UUID */
    Uuid,
}

#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

type KeepaliveManager = Arc<RwLock<HashMap<String, Arc<dyn Any + Send + Sync>>>>;

/** forward data between inbound and outbound */
async fn handle_forwarding<I, O>(inbound: I, outbound: O) -> IOResult<()>
where
    I: ProxyConnection + 'static,
    O: ProxyConnection + 'static,
{
    let (inbound_read, inbound_write) = inbound.split();
    let (outbound_read, outbound_write) = outbound.split();
    let i_to_o: JoinHandle<IOResult<()>> = tokio::spawn(async move {
        let mut buf = vec![0; common::BUF_SIZE];
        loop {
            let (read_size, net) = inbound_read.receive(&mut buf).await?;
            /* connection is down */
            if read_size == 0 {
                return Ok(());
            }
            outbound_write.send(&buf[..read_size], net).await?;
        }
    });

    let o_to_i: JoinHandle<IOResult<()>> = tokio::spawn(async move {
        let mut buf = vec![0; common::BUF_SIZE];
        loop {
            let (read_size, net) = outbound_read.receive(&mut buf).await?;
            /* connection is down */
            if read_size == 0 {
                return Ok(());
            }
            inbound_write.send(&buf[..read_size], net).await?;
        }
    });

    loop {
        if o_to_i.is_finished() {
            i_to_o.abort();
            break;
        }
        if o_to_i.is_finished() {
            i_to_o.abort();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn process_outbound<C>(
    outbound_config: Outbound,
    kp_mgr: KeepaliveManager,
    dst_addr: Addr,
    dst_port: u16,
    inbound: C,
) -> anyhow::Result<()>
where
    C: ProxyConnection + 'static,
{
    match outbound_config {
        Outbound::Direct { .. } => {
            let direct_connection =
                direct::DirectConnection::connect(dst_addr.to_socket_addr(dst_port)).await?;
            handle_forwarding(inbound, direct_connection).await?;
        }
        Outbound::Reject { .. } => {
            let reject_connection = reject::DirectConnection::default();
            handle_forwarding(inbound, reject_connection).await?;
        }
        Outbound::Socks5 { server, port, .. } => {
            let socks5_server =
                socks5::Socks5Client::connect(to_sock_addr(&server, port), dst_addr, dst_port)
                    .await?;

            handle_forwarding(inbound, socks5_server).await?;
        }
        Outbound::Anytls {
            server,
            port,
            password,
            tls,
            ..
        } => {
            use anytls::AnytlsConnector;

            let mut anytls_connector = AnytlsConnector::default();
            if let Some(tls) = tls {
                anytls_connector =
                    anytls_connector.insecure(tls.insecure.unwrap_or(TLS_INSECURE_DEFAULT));
                if let Some(sni) = &tls.sni {
                    anytls_connector = anytls_connector.sni(sni);
                }
            }

            let anytls_server = anytls_connector
                .password(password)
                .connect(to_sock_addr(&server, port), dst_addr, dst_port)
                .await?;

            handle_forwarding(inbound, anytls_server).await?;
        }
        Outbound::Trojan {
            server,
            port,
            password,
            tls,
            ..
        } => {
            use trojan::TrojanConnector;

            let mut trojan_connector = TrojanConnector::default();
            if let Some(tls) = tls {
                trojan_connector =
                    trojan_connector.insecure(tls.insecure.unwrap_or(TLS_INSECURE_DEFAULT));
                if let Some(sni) = &tls.sni {
                    trojan_connector = trojan_connector.sni(sni);
                }
            }

            let trojan_server = trojan_connector
                .password(password)
                .connect(to_sock_addr(&server, port), dst_addr, dst_port)
                .await?;

            handle_forwarding(inbound, trojan_server).await?;
        }
        Outbound::Shadowsocks {
            server,
            port,
            password,
            method,
            ..
        } => {
            use shadowsocks::{Method, ShadowsocksConnector};

            let cipher = Method::from_str(method.as_str()).unwrap();

            let ss_client = ShadowsocksConnector::default()
                .method(cipher)
                .password(password)
                .connect(to_sock_addr(&server, port), dst_addr.clone(), dst_port)
                .await?;

            handle_forwarding(inbound, ss_client).await?;
        }
        Outbound::Vmess {
            server,
            port,
            uuid,
            tls,
            ..
        } => {
            if let Some(tls_config) = tls {
                let stream =
                    transport::connect_tls(to_sock_addr(&server, port), tls_config).await?;
                let vmess_client = vmess::VMessConnector::default()
                    .uuid(Uuid::from_str(&uuid)?)
                    .connect(stream, dst_addr.clone(), dst_port)
                    .await?;
                handle_forwarding(inbound, vmess_client).await?;
            } else {
                let stream = transport::connect_tcp(to_sock_addr(&server, port)).await?;
                let vmess_client = vmess::VMessConnector::default()
                    .uuid(Uuid::from_str(&uuid)?)
                    .connect(stream, dst_addr.clone(), dst_port)
                    .await?;
                handle_forwarding(inbound, vmess_client).await?;
            }
        }
        Outbound::Vless {
            server,
            port,
            uuid,
            tls,
            ..
        } => {
            use vless::VlessConnector;

            let vless_builder = VlessConnector::default().uuid(Uuid::from_str(&uuid)?);

            if let Some(tls_config) = tls {
                let stream =
                    transport::connect_tls(to_sock_addr(&server, port), tls_config).await?;
                let vless_client = vless_builder
                    .connect(stream, dst_addr.clone(), dst_port)
                    .await?;

                handle_forwarding(inbound, vless_client).await?;
            } else {
                let stream = transport::connect_tcp(to_sock_addr(&server, port)).await?;
                let vless_client = vless_builder
                    .connect(stream, dst_addr.clone(), dst_port)
                    .await?;

                handle_forwarding(inbound, vless_client).await?;
            }
        }
        Outbound::Hysteria2 {
            name,
            server,
            port,
            password,
            tls,
            ..
        } => {
            if let Some(conn) = kp_mgr.read().await.get(&name) {
                let conn = conn.downcast_ref::<Hysteria2Keepalive>().unwrap();
                if let Ok(hy2_client) = conn.connect(dst_addr.clone(), dst_port).await {
                    handle_forwarding(inbound, hy2_client).await?;
                    return Ok(());
                }
            }

            use hysteria2::Hysteria2Connector;

            let mut hy2_connector = Hysteria2Connector::default().password(password);
            if let Some(tls) = tls {
                hy2_connector =
                    hy2_connector.insecure(tls.insecure.unwrap_or(TLS_INSECURE_DEFAULT));
                if let Some(sni) = &tls.sni {
                    hy2_connector = hy2_connector.sni(sni);
                }
            }

            let hy2_keepalive = hy2_connector.connect(to_sock_addr(&server, port)).await?;
            let hy2_client = hy2_keepalive.connect(dst_addr, dst_port).await?;

            kp_mgr.write().await.insert(name, Arc::new(hy2_keepalive));

            handle_forwarding(inbound, hy2_client).await?;
        }
        #[cfg(feature = "ssh")]
        Outbound::Ssh {
            name,
            server,
            port,
            username,
            password,
            private_key_path,
            private_key_passphrase,
            ..
        } => {
            use ssh::{Authorization, SshKeepalive};

            if let Some(conn) = kp_mgr.read().await.get(&name) {
                let conn = conn.downcast_ref::<SshKeepalive>().unwrap();
                if let Ok(hy2_client) = conn.connect(dst_addr.clone(), dst_port).await {
                    handle_forwarding(inbound, hy2_client).await?;
                    return Ok(());
                }
            }

            let auth;
            if let Some(password) = password {
                auth = Authorization::Password { username, password };
            } else if let Some(key_path) = private_key_path {
                auth = Authorization::PrivateKey {
                    username,
                    key: tokio::fs::read_to_string(key_path).await?,
                    passphrase: private_key_passphrase,
                };
            } else {
                return Err(anyhow::Error::msg("No authorization method found"));
            }

            let ssh_keepalive = SshKeepalive::connect(to_sock_addr(&server, port), auth).await?;
            let ssh_client = ssh_keepalive.connect(dst_addr, dst_port).await?;

            kp_mgr.write().await.insert(name, Arc::new(ssh_keepalive));

            handle_forwarding(inbound, ssh_client).await?;
        }
    }

    Ok(())
}

async fn handshake<C>(
    client: C,
    kp_mgr: KeepaliveManager,
    src_addr: SocketAddr,
    outbounds: Vec<Outbound>,
    router: Arc<Router>,
) -> anyhow::Result<()>
where
    C: ProxyHandshake + 'static,
{
    let (client, (dst_addr, dst_port)) = client.handshake().await?;

    let selected_outbound = router.get_outbound(dst_addr.clone().into());

    log::info!(
        "forward: {} -> tcp://{} using {}",
        src_addr,
        dst_addr.to_socket_addr(dst_port),
        selected_outbound
    );

    for outbound in outbounds {
        if outbound.get_name() == selected_outbound {
            process_outbound(outbound.clone(), kp_mgr, dst_addr, dst_port, client).await?;
            break;
        }
    }
    Ok(())
}

/** call `ProxyServer::accept` to accept a connection and call `process_outbound` to start forwarding. */
async fn handle_accept<S>(
    mut server: S,
    kp_mgr: KeepaliveManager,
    outbounds: &[Outbound],
    router: Arc<Router>,
) -> IOResult<()>
where
    S: ProxyServer + 'static,
{
    loop {
        let client;
        let src_addr;
        match server.accept().await {
            Ok((clt, src)) => {
                client = clt;
                src_addr = src;
            }
            Err(err) => {
                log::error!("{}", err);
                continue;
            }
        };

        tokio::spawn(handshake(
            client,
            Arc::clone(&kp_mgr),
            src_addr,
            outbounds.to_vec(),
            Arc::clone(&router),
        ));
    }
}

async fn process_inbound(
    inbound: Inbound,
    outbounds: Vec<Outbound>,
    router: Arc<Router>,
    kp_mgr: KeepaliveManager,
) -> anyhow::Result<()> {
    match inbound {
        Inbound::Socks5 { listen, port, .. } => {
            let socks5_server = socks5::Socks5Server::listen(&listen, port).await?;

            handle_accept(socks5_server, Arc::clone(&kp_mgr), &outbounds, router).await?;
        }
        #[cfg(feature = "tun")]
        Inbound::Tun { address } => {
            let tun_controller = neko_tun::TunBuilder::default()
                .address(&address)
                .create()
                .await?;

            handle_accept(tun_controller, Arc::clone(&kp_mgr), &outbounds, router).await?;
        }
        Inbound::Trojan {
            listen,
            port,
            passwords,
            tls,
        } => {
            let mut trojan_builder = trojan::TrojanServerBuilder::default();
            for password in passwords {
                trojan_builder = trojan_builder.add_password(password);
            }

            if let Some(file) = tls.cert_path {
                trojan_builder = trojan_builder.add_cert_chain(&tokio::fs::read(file).await?);
            }
            if let Some(file) = tls.key_path {
                trojan_builder = trojan_builder.add_key_der(&tokio::fs::read(file).await?);
            }

            let trojan_server = trojan_builder.listen(to_sock_addr(&listen, port)).await?;

            handle_accept(trojan_server, Arc::clone(&kp_mgr), &outbounds, router).await?;
        }
        Inbound::Shadowsocks {
            listen,
            port,
            password,
            method,
        } => {
            use shadowsocks::{Method, ShadowsocksServer};
            let cipher = Method::from_str(method.as_str()).unwrap();

            let ss_server =
                ShadowsocksServer::bind(to_sock_addr(&listen, port), cipher, &password).await?;

            handle_accept(ss_server, Arc::clone(&kp_mgr), &outbounds, router).await?;
        }
        Inbound::Vless {
            listen,
            port,
            uuids,
            ..
        } => {
            let mut vless_builder = vless::VlessServerBuilder::default();
            for uuid in uuids {
                vless_builder = vless_builder.add_uuid(Uuid::from_str(&uuid)?);
            }

            let vless_server = vless_builder.listen(to_sock_addr(&listen, port)).await?;

            handle_accept(vless_server, Arc::clone(&kp_mgr), &outbounds, router).await?;
        }
    }
    Ok(())
}

async fn run_config<P>(config: P) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    let config: config::Config =
        serde_yaml_ng::from_str(&tokio::fs::read_to_string(config).await?)?;
    let router = Arc::new(Router::from_config(&config));

    let kp_mgr = KeepaliveManager::default();
    let mut handlers = Vec::new();

    for inbound in config.inbounds {
        let handle = tokio::spawn(process_inbound(
            inbound,
            config.outbounds.clone(),
            Arc::clone(&router),
            Arc::clone(&kp_mgr),
        ));
        handlers.push(handle);
    }

    for handle in handlers {
        handle.await??;
    }

    Ok(())
}

fn rustls_set_default_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();
    rustls_set_default_provider();

    match args.command {
        Command::Run { config } => run_config(config).await?,
        Command::Tools { command } => match command {
            ToolsCommand::Uuid => {
                println!("{}", Uuid::new_v4());
            }
        },
    }

    Ok(())
}
