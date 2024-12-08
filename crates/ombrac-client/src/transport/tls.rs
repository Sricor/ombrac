use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ombrac::Provider;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use super::Result;

type Stream = TlsStream<TcpStream>;

pub struct Tls(Receiver<Stream>);

impl Tls {
    async fn new(mut options: Builder) -> Result<Self> {
        let client_config = ClientConfig::builder()
            .with_root_certificates(options.root_cert_store()?)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(client_config));
        let domain = ServerName::try_from(options.host.as_str())?.to_owned();

        let (sender, receiver) = mpsc::channel(8);

        tokio::spawn(async move {
            use crate::{debug_timer, try_or_continue};

            loop {
                let addr = try_or_continue!(options.ip().await);
                let stream = try_or_continue!(TcpStream::connect(&addr).await);
                let stream = debug_timer!(
                    "TLS took",
                    try_or_continue!(connector.connect(domain.clone(), stream).await)
                );

                if sender.send(stream).await.is_err() {
                    break;
                }
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
    host: String,
    port: u16,
    ip: Option<(SocketAddr, Instant)>,
    tls_cert: Option<PathBuf>,
    ip_cache_duration: Duration,
}

impl Builder {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            ip: None,
            tls_cert: None,
            ip_cache_duration: Duration::from_secs(1800),
        }
    }

    pub fn with_tls_cert(mut self, tls_cert: PathBuf) -> Self {
        self.tls_cert = Some(tls_cert);

        self
    }

    pub fn with_ip_cache_duration(mut self, ip_cache_duration: Duration) -> Self {
        self.ip_cache_duration = ip_cache_duration;

        self
    }

    pub async fn build(self) -> Result<Tls> {
        Tls::new(self).await
    }

    async fn ip(&mut self) -> Result<SocketAddr> {
        use tokio::net::lookup_host;

        if let Some((cached_ip, cached_at)) = &self.ip {
            if cached_at.elapsed() < self.ip_cache_duration {
                return Ok(*cached_ip);
            }
        }

        let addr = lookup_host((self.host.as_str(), self.port))
            .await?
            .next()
            .ok_or(io::Error::other(format!(
                "unable to resolve address '{}'",
                self.host
            )))?;

        self.ip = Some((addr, Instant::now()));

        Ok(addr)
    }

    fn root_cert_store(&self) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();

        if let Some(tls_cert) = &self.tls_cert {
            for cert in CertificateDer::pem_file_iter(tls_cert)? {
                store.add(cert?)?;
            }
        } else {
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        Ok(store)
    }
}
