use crate::config::{TLS_INSECURE_DEFAULT, TLSSetting};
use common::SkipServerVerification;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::{io::Result as IOResult, sync::Arc};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{TlsConnector, client::TlsStream};

pub async fn connect_tcp<A>(addr: A) -> IOResult<TcpStream>
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(addr).await?;
    Ok(stream)
}

pub async fn connect_tls<A>(addr: A, tls_config: TLSSetting) -> IOResult<TlsStream<TcpStream>>
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(addr).await?;

    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();

    if tls_config.insecure.unwrap_or(TLS_INSECURE_DEFAULT) {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipServerVerification));
    }

    let sni = tls_config.sni.unwrap_or_default();

    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from(sni).unwrap();
    let tls = connector.connect(domain, stream).await?;

    Ok(tls)
}
