use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use ombrac::Provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{rustls, TlsAcceptor};

pub struct Builder {
    listen: String,

    tls_key: String,
    tls_cert: String,
}

impl Builder {
    pub fn new(listen: String, tls_cert: String, tls_key: String) -> Self {
        Self { listen, tls_cert, tls_key }
    }

    pub async fn build(self) -> io::Result<Tls> {
        Tls::new(self).await
    }
}

type Stream = TlsStream<TcpStream>;

pub struct Tls(Receiver<Stream>);

impl Provider for Tls {
    type Item = Stream;

    async fn fetch(&mut self) -> Option<Self::Item> {
        self.0.recv().await
    }
}

impl Tls {
    async fn new(options: Builder) -> io::Result<Self> {

    let addr = options
        .listen
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let certs = CertificateDer::pem_file_iter(&options.tls_cert).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = PrivateKeyDer::from_pem_file(&options.tls_key).unwrap();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;

    let (sender, receiver) = mpsc::channel(1);

    tokio::spawn(async move {
        while let Ok((stream, _peer_addr)) = listener.accept().await {
            let acceptor = acceptor.clone();

            let stream = acceptor.accept(stream).await.unwrap();

            if sender.send(stream).await.is_err() {
                break;
            }
        }
    });

    Ok(Self(receiver))

    }
}