use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use quinn::congestion;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use tokio::sync::mpsc;

use super::{Connection, Result, Stream};

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

    pub async fn build(self) -> Result<Connection> {
        Connection::with_server(self).await
    }
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

impl Connection {
    async fn with_server(config: Builder) -> Result<Self> {
        let key = crate::tls::load_private_key(&config.tls_key)?;
        let certs = crate::tls::load_certificates(&config.tls_cert)?;

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

        let endpoint = Endpoint::server(server_config, config.listen.parse()?)?;

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let connection = match conn.await {
                    Ok(value) => value,
                    Err(_error) => {
                        eprintln!("{}", _error);
                        continue;
                    }
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
                                return;
                            }
                            Ok(s) => sender.send(Stream(s.0, s.1)).await.unwrap(),
                        };
                    }
                });
            }
        });

        Ok(Connection(receiver))
    }
}
