use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use ombrac::Provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls, TlsConnector};

pub struct Builder {
    host: String,
    port: u16,
    domain: Option<String>,
    cafile: Option<PathBuf>,
}

impl Builder {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port, domain: None, cafile: None }
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
        let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        let domain = options.domain.unwrap_or(options.host);

        let mut root_cert_store = rustls::RootCertStore::empty();

        if let Some(cafile) = &options.cafile {
            for cert in CertificateDer::pem_file_iter(cafile).unwrap() {
                root_cert_store.add(cert.unwrap()).unwrap();
            }
        } else {
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let options = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let domain = ServerName::try_from(domain.as_str()).unwrap().to_owned();
        let connector = TlsConnector::from(Arc::new(options));

        let (sender, receiver) = mpsc::channel(1);
        
        tokio::spawn(async move {
            loop {
                let stream = TcpStream::connect(&addr).await.unwrap();
                let stream = connector.connect(domain.clone(), stream).await.unwrap();

                if sender.send(stream).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self(receiver))
    }
}