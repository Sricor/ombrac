use std::path::{Path, PathBuf};
use std::time::Duration;

use ombrac::Provider;
use tokio::sync::mpsc;
use quinn::{SendStream, RecvStream};

use crate::info;

use super::Result;

pub struct Stream (SendStream, RecvStream);

pub struct Quic(mpsc::Receiver<Stream>);

impl Provider for Quic {
    type Item = Stream;

    async fn fetch(&mut self) -> Option<Self::Item> {
        self.0.recv().await
    }
}

pub struct Builder {
    listen: String,

    tls_key: PathBuf,
    tls_cert: PathBuf,

    initial_congestion_window: Option<u32>,

    max_handshake_duration: Option<Duration>,
    max_idle_timeout: Option<Duration>,
    max_keep_alive_period: Option<Duration>,
    max_open_bidirectional_streams: Option<u64>,

    bidirectional_local_data_window: Option<u64>,
    bidirectional_remote_data_window: Option<u64>,
}

impl Builder {
    pub fn new(listen: String, tls_cert: PathBuf, tls_key: PathBuf) -> Self {
        Builder {
            listen,
            tls_cert,
            tls_key,
            initial_congestion_window: None,
            max_handshake_duration: None,
            max_idle_timeout: None,
            max_keep_alive_period: None,
            max_open_bidirectional_streams: None,
            bidirectional_local_data_window: None,
            bidirectional_remote_data_window: None,
        }
    }

    pub fn with_tls_cert(mut self, value: PathBuf) -> Self {
        self.tls_cert = value;
        self
    }

    pub fn with_tls_key(mut self, value: PathBuf) -> Self {
        self.tls_key = value;
        self
    }

    pub fn with_initial_congestion_window(mut self, value: u32) -> Self {
        self.initial_congestion_window = Some(value);
        self
    }

    pub fn with_max_handshake_duration(mut self, value: Duration) -> Self {
        self.max_handshake_duration = Some(value);
        self
    }

    pub fn with_max_idle_timeout(mut self, value: Duration) -> Self {
        self.max_idle_timeout = Some(value);
        self
    }

    pub fn with_max_keep_alive_period(mut self, value: Duration) -> Self {
        self.max_keep_alive_period = Some(value);
        self
    }

    pub fn with_max_open_bidirectional_streams(mut self, value: u64) -> Self {
        self.max_open_bidirectional_streams = Some(value);
        self
    }

    pub fn with_bidirectional_local_data_window(mut self, value: u64) -> Self {
        self.bidirectional_local_data_window = Some(value);
        self
    }

    pub fn with_bidirectional_remote_data_window(mut self, value: u64) -> Self {
        self.bidirectional_remote_data_window = Some(value);
        self
    }

    pub async fn build(self) -> Result<Quic> {
        Quic::new(self).await
    }
}

impl Quic {
    async fn new(config: Builder) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(1);

        let mut server = s2n_server_with_config(&config).await?;

        tokio::spawn(async move {
            while let Some(mut connection) = server.accept().await {
                if sender.is_closed() {
                    break;
                }

                let sender = sender.clone();

                tokio::spawn(async move {
                    info!(
                        "{:?} accept connection {} from {:?}",
                        connection.server_name(),
                        connection.id(),
                        connection.remote_addr()
                    );

                    while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                        if sender.send(stream).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        Ok(Self(receiver))
    }
}

mod impl_quinn {
    use std::sync::Arc;
    use std::fs;

    use quinn::congestion;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::{Builder, Quic, Result};

    pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

    pub(super) async fn quinn_server_with_config(config: &Builder) -> Result<Quic> {
        rustls::crypto::aws_lc_rs::default_provider().install_default().expect("Failed to install rustls crypto provider");
    
        let (certs, key ) = {
            let key_path = &config.tls_key;
            let cert_path = &config.tls_cert;
            let key = fs::read(key_path).unwrap();
            let key = if key_path.extension().is_some_and(|x| x == "der") {
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
            } else {
                rustls_pemfile::private_key(&mut &*key)
                    .unwrap()
                    .ok_or_else(|| Error(io::Error::))?
            };
            let cert_chain = fs::read(cert_path).unwrap();
            let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
                vec![CertificateDer::from(cert_chain)]
            } else {
                rustls_pemfile::certs(&mut &*cert_chain)
                    .collect::<Result<_, _>>()
                    .context("invalid PEM-encoded certificate")?
            };
    
            (cert_chain, key)
        };
    
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        
        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
    
        let endpoint = quinn::Endpoint::server(server_config, config.listen.parse().unwrap())?;
    
        let (sender, receiver) = mpsc::channel(1);
    
        
        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let connection = match conn.await {
                    Ok(value) => value,
                    Err(_error) => {eprintln!("{}", _error); continue;}
                };
    
                let sender = sender.clone();
                tokio::spawn(async move {
                    loop {
                        let stream = connection.accept_bi().await;
                        match stream {
                            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                                return;
                            }
                            Err(e) => {
                                eprintln!("connection error {}", e);
                                continue;
                            }
                            Ok(s) => sender.send(Stream(s.0, s.1)).await.unwrap(),
                        };
                    };
                });
            }
        });
        
    
        Ok(Quic(receiver))
    }
}


async fn s2n_server_with_config(config: &Builder) -> Result<Server> {
    use s2n_quic::provider::congestion_controller;
    use s2n_quic::provider::limits;

    let limits = {
        let mut limits = limits::Limits::new();

        if let Some(value) = config.bidirectional_local_data_window {
            limits = limits.with_bidirectional_local_data_window(value)?;
        }

        if let Some(value) = config.bidirectional_remote_data_window {
            limits = limits.with_bidirectional_remote_data_window(value)?;
        }

        if let Some(value) = config.max_open_bidirectional_streams {
            limits = limits.with_max_open_local_bidirectional_streams(value)?;
        }

        if let Some(value) = config.max_open_bidirectional_streams {
            limits = limits.with_max_open_remote_bidirectional_streams(value)?;
        }

        if let Some(value) = config.max_handshake_duration {
            limits = limits.with_max_handshake_duration(value)?;
        }

        if let Some(value) = config.max_keep_alive_period {
            limits = limits.with_max_keep_alive_period(value)?;
        }

        if let Some(value) = config.max_idle_timeout {
            limits = limits.with_max_idle_timeout(value)?;
        }

        limits
    };

    let controller = {
        let mut controller = congestion_controller::bbr::Builder::default();

        if let Some(value) = config.initial_congestion_window {
            controller = controller.with_initial_congestion_window(value);
        }

        controller.build()
    };

    let server = Server::builder()
        .with_io(config.listen.as_str())?
        .with_limits(limits)?
        .with_congestion_controller(controller)?
        .with_tls((Path::new(&config.tls_cert), Path::new(&config.tls_key)))?
        .start()?;

    Ok(server)
}