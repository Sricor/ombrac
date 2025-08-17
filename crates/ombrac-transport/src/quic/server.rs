use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_channel::Receiver;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;

use crate::Acceptor;
#[cfg(feature = "datagram")]
use crate::quic::datagram::Datagram;

use super::{Congestion, Result, error::Error, stream::Stream};

pub struct Builder {
    listen: SocketAddr,
    enable_zero_rtt: bool,
    enable_self_signed: bool,
    tls_paths: Option<(PathBuf, PathBuf)>,
    transport_config: TransportConfig,
}

impl Builder {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            tls_paths: None,
            enable_zero_rtt: false,
            enable_self_signed: false,
            transport_config: TransportConfig::default(),
        }
    }

    pub fn with_tls(&mut self, paths: (PathBuf, PathBuf)) -> &mut Self {
        self.tls_paths = Some(paths);
        self
    }

    pub fn with_enable_zero_rtt(&mut self, value: bool) -> &mut Self {
        self.enable_zero_rtt = value;
        self
    }

    pub fn with_enable_self_signed(&mut self, value: bool) -> &mut Self {
        self.enable_self_signed = value;
        self
    }

    pub fn with_congestion(
        &mut self,
        congestion: Congestion,
        initial_window: Option<u64>,
    ) -> &mut Self {
        use quinn::congestion;

        let congestion: Arc<dyn congestion::ControllerFactory + Send + Sync + 'static> =
            match congestion {
                Congestion::Bbr => {
                    let mut config = congestion::BbrConfig::default();
                    if let Some(value) = initial_window {
                        config.initial_window(value);
                    }
                    Arc::new(config)
                }
                Congestion::Cubic => {
                    let mut config = congestion::CubicConfig::default();
                    if let Some(value) = initial_window {
                        config.initial_window(value);
                    }
                    Arc::new(config)
                }
                Congestion::NewReno => {
                    let mut config = congestion::NewRenoConfig::default();
                    if let Some(value) = initial_window {
                        config.initial_window(value);
                    }
                    Arc::new(config)
                }
            };

        self.transport_config
            .congestion_controller_factory(congestion);
        self
    }

    pub fn with_max_idle_timeout(&mut self, value: Duration) -> Result<&mut Self> {
        use quinn::IdleTimeout;
        self.transport_config
            .max_idle_timeout(Some(IdleTimeout::try_from(value)?));
        Ok(self)
    }

    pub fn with_max_keep_alive_period(&mut self, value: Duration) -> &mut Self {
        self.transport_config.keep_alive_interval(Some(value));
        self
    }

    pub fn with_max_open_bidirectional_streams(&mut self, value: u64) -> Result<&mut Self> {
        self.transport_config
            .max_concurrent_bidi_streams(VarInt::try_from(value)?);
        Ok(self)
    }

    pub async fn build(self) -> Result<QuicServer> {
        let server_config = self.build_server_config()?;

        QuicServer::with_server(Endpoint::server(server_config, self.listen)?).await
    }

    fn build_server_config(&self) -> Result<ServerConfig> {
        let (certs, key) = if self.enable_self_signed {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
            let certs = vec![CertificateDer::from(cert.cert)];
            (certs, key)
        } else {
            let (cert, key) = self
                .tls_paths
                .as_ref()
                .ok_or(Error::ServerMissingCertificate)?;
            let certs = super::load_certificates(cert)?;
            let key = super::load_private_key(key)?;
            (certs, key)
        };

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        // Zero RTT
        if self.enable_zero_rtt {
            server_crypto.send_half_rtt_data = true;
            server_crypto.max_early_data_size = u32::MAX;
        }

        let server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

        Ok(server_config)
    }
}

impl QuicServer {
    async fn with_server(endpoint: Endpoint) -> Result<Self> {
        let (sender, receiver) = async_channel::unbounded();

        #[cfg(feature = "datagram")]
        let (datagram_sender, datagram_receiver) = async_channel::unbounded();

        let handle = tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let sender = sender.clone();

                #[cfg(feature = "datagram")]
                let datagram_sender = datagram_sender.clone();

                tokio::spawn(async move {
                    let connection = match connecting.await {
                        Ok(conn) => conn,
                        Err(_) => return,
                    };

                    #[cfg(feature = "datagram")]
                    {
                        use crate::quic::datagram::Session;

                        let conn = connection.clone();
                        tokio::spawn(async move {
                            let session = Session::with_server(conn);

                            while let Some(datagram) = session.accept_datagram().await {
                                if datagram_sender.send(datagram).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }

                    while let Ok((send_stream, recv_stream)) = connection.accept_bi().await {
                        if sender.send(Stream(send_stream, recv_stream)).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        Ok(QuicServer {
            handle,
            stream: receiver,
            #[cfg(feature = "datagram")]
            datagram: datagram_receiver,
        })
    }
}

pub struct QuicServer {
    handle: JoinHandle<()>,
    #[cfg(feature = "datagram")]
    datagram: Receiver<Datagram>,
    stream: Receiver<Stream>,
}

impl Acceptor for QuicServer {
    async fn accept_bidirectional(&self) -> io::Result<impl crate::Reliable> {
        self.stream.recv().await.map_err(io::Error::other)
    }

    #[cfg(feature = "datagram")]
    async fn accept_datagram(&self) -> io::Result<impl crate::Unreliable> {
        self.datagram.recv().await.map_err(io::Error::other)
    }
}
