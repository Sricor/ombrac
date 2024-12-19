use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use std::path::PathBuf;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{congestion, VarInt};
use tokio::sync::mpsc;

use super::{Connection, Result, Stream};

pub struct Builder {
    bind: Option<String>,

    server_name: Option<String>,
    server_address: String,

    tls_cert: Option<PathBuf>,

    initial_congestion_window: Option<u32>,

    max_handshake_duration: Option<Duration>,
    max_idle_timeout: Option<Duration>,
    max_keep_alive_period: Option<Duration>,
    max_open_bidirectional_streams: Option<u64>,

    bidirectional_local_data_window: Option<u64>,
    bidirectional_remote_data_window: Option<u64>,
}

impl Builder {
    pub fn new(server_address: String) -> Self {
        Builder {
            bind: None,
            server_name: None,
            server_address,
            tls_cert: None,
            initial_congestion_window: None,
            max_handshake_duration: None,
            max_idle_timeout: None,
            max_keep_alive_period: None,
            max_open_bidirectional_streams: None,
            bidirectional_local_data_window: None,
            bidirectional_remote_data_window: None,
        }
    }

    pub fn with_server_name(mut self, value: String) -> Self {
        self.server_name = Some(value);
        self
    }

    pub fn with_bind(mut self, value: String) -> Self {
        self.bind = Some(value);
        self
    }

    pub fn with_tls_cert(mut self, value: PathBuf) -> Self {
        self.tls_cert = Some(value);
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
        Connection::with_client(self).await
    }

    fn server_name(&self) -> Result<&str> {
        match &self.server_name {
            Some(value) => Ok(value),
            None => {
                let pos = self
                    .server_address
                    .rfind(':')
                    .ok_or(format!("invalid server address {}", self.server_address))?;

                Ok(&self.server_address[..pos])
            }
        }
    }

    async fn server_address(&self) -> Result<SocketAddr> {
        use tokio::net::lookup_host;

        let address = lookup_host(&self.server_address)
            .await?
            .next()
            .ok_or(format!(
                "failed to resolve address '{}'",
                self.server_address
            ))?;

        Ok(address)
    }
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

impl Connection {
    async fn with_client(config: Builder) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();

        if let Some(path) = &config.tls_cert {
            let certs = super::load_certificates(path)?;
            roots.add_parsable_certificates(certs);
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));

        let mut transport_config = quinn::TransportConfig::default();

        transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

        let mut endpoint = quinn::Endpoint::client(
            (&config.bind.clone().unwrap_or("0.0.0.0:0".to_string()))
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        )?;
        endpoint.set_default_client_config(client_config);

        let server_name = config.server_name()?.to_string();
        let server_address = config.server_address().await?;

        let (sender, receiver) = mpsc::channel(1);

        tokio::spawn(async move {
            'connection: loop {
                let connection = match endpoint.connect(server_address, &server_name.clone()) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("connection: {}", error);
                        continue;
                    }
                };

                let connection = match connection.await {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("connection await error {}", error);
                        continue;
                    }
                };

                'stream: loop {
                    let stream = match connection.open_bi().await {
                        Ok(value) => Stream(value.0, value.1),
                        Err(error) => {
                            eprintln!("stream error {}", error);

                            break 'stream;
                        }
                    };

                    if sender.send(stream).await.is_err() {
                        break 'connection;
                    }
                }
            }
        });

        Ok(Connection(receiver))
    }
}
