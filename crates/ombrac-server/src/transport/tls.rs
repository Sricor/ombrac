use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ombrac::Provider;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::Result;

type Stream = TlsStream<TcpStream>;

pub struct Tls(Receiver<Stream>);

impl Tls {
    async fn new(options: Builder) -> Result<Self> {
        let listener = TcpListener::bind(options.listen).await?;
        let key = PrivateKeyDer::from_pem_file(&options.tls_key)?;
        let certs = CertificateDer::pem_file_iter(&options.tls_cert)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            use crate::{debug, try_or_return};

            while let Ok((stream, _peer_addr)) = listener.accept().await {
                if sender.is_closed() {
                    break;
                }

                let sender = sender.clone();
                let acceptor = acceptor.clone();

                tokio::spawn(async move {
                    debug!(
                        "{:?} accept connection from {:?}",
                        stream.local_addr(),
                        _peer_addr
                    );

                    let stream = try_or_return!(acceptor.accept(stream).await);

                    if sender.send(stream).await.is_err() {
                        return;
                    }
                });
            }
        });

        Ok(Self(receiver))
    }
}

impl Provider for Tls {
    type Item = Stream;

    async fn fetch(&mut self) -> Option<Self::Item> {
        self.0.recv().await
    }
}

pub struct Builder {
    listen: SocketAddr,

    tls_key: PathBuf,
    tls_cert: PathBuf,
}

impl Builder {
    pub fn new(listen: SocketAddr, tls_cert: PathBuf, tls_key: PathBuf) -> Self {
        Self {
            listen,
            tls_cert,
            tls_key,
        }
    }

    pub async fn build(self) -> Result<Tls> {
        Tls::new(self).await
    }
}
