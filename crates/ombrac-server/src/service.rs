use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use ombrac_macros::{error, warn};
#[cfg(feature = "transport-quic")]
use ombrac_transport::quic::{
    Connection as QuicConnection, TransportConfig as QuicTransportConfig,
    server::{Config as QuicConfig, Server as QuicServer},
};
use ombrac_transport::{Acceptor, Connection};

use crate::config::{ServiceConfig, TlsMode};
use crate::server::Server;

pub trait ServiceBuilder {
    type Acceptor: Acceptor<Connection = Self::Connection>;
    type Connection: Connection;

    fn build(
        config: &Arc<ServiceConfig>,
    ) -> impl Future<Output = io::Result<Arc<Server<Self::Acceptor>>>> + Send;
}

pub struct QuicServiceBuilder;

impl ServiceBuilder for QuicServiceBuilder {
    type Acceptor = QuicServer;
    type Connection = QuicConnection;

    async fn build(config: &Arc<ServiceConfig>) -> io::Result<Arc<Server<Self::Acceptor>>> {
        let acceptor = quic_server_from_config(config).await?;
        let secret = *blake3::hash(config.secret.as_bytes()).as_bytes();
        let server = Arc::new(Server::new(acceptor, secret));
        Ok(server)
    }
}

pub struct Service<T, C>
where
    T: Acceptor<Connection = C>,
    C: Connection,
{
    handle: JoinHandle<io::Result<()>>,
    shutdown_tx: broadcast::Sender<()>,
    _acceptor: PhantomData<T>,
    _connection: PhantomData<C>,
}

impl<T, C> Service<T, C>
where
    T: Acceptor<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    pub async fn build<Builder>(config: Arc<ServiceConfig>) -> io::Result<Self>
    where
        Builder: ServiceBuilder<Acceptor = T>,
    {
        #[cfg(feature = "tracing")]
        setup_logging(&config.logging);

        let server = Builder::build(&config).await?;
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let handle = tokio::spawn(async move { server.accept_loop(shutdown_rx).await });

        Ok(Service {
            handle,
            shutdown_tx,
            _acceptor: PhantomData,
            _connection: PhantomData,
        })
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        if let Err(_err) = self.handle.await {
            error!("The main server task failed: {:?}", _err);
        }
        warn!("Service shutdown complete");
    }
}

#[cfg(feature = "tracing")]
fn setup_logging(config: &crate::config::LoggingConfig) {
    let log_level = config
        .log_level
        .as_deref()
        .map(|level_str| {
            level_str.parse().unwrap_or_else(|_| {
                warn!("Invalid log level '{}', defaulting to WARN", level_str);
                tracing::Level::WARN
            })
        })
        .unwrap_or(tracing::Level::WARN);

    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_max_level(log_level);

    let (non_blocking, guard) = if let Some(path) = &config.log_dir {
        let prefix = config
            .log_prefix
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("log"));
        let file_appender = tracing_appender::rolling::daily(path, prefix);
        tracing_appender::non_blocking(file_appender)
    } else {
        tracing_appender::non_blocking(std::io::stdout())
    };

    // The guard must be held for the lifetime of the program.
    std::mem::forget(guard);
    subscriber.with_writer(non_blocking).init();
}

#[cfg(feature = "transport-quic")]
async fn quic_server_from_config(config: &ServiceConfig) -> io::Result<QuicServer> {
    let transport_cfg = &config.transport;
    let mut quic_config = QuicConfig::new();

    quic_config.enable_zero_rtt = transport_cfg.zero_rtt.unwrap_or(false);
    if let Some(protocols) = &transport_cfg.alpn_protocols {
        quic_config.alpn_protocols = protocols.clone();
    }

    match transport_cfg.tls_mode.unwrap_or(TlsMode::Tls) {
        TlsMode::Tls => {
            let cert_path = transport_cfg.tls_cert.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls_cert is required for TLS mode",
                )
            })?;
            let key_path = transport_cfg.tls_key.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls_key is required for TLS mode",
                )
            })?;
            quic_config.tls_cert_key_paths = Some((cert_path, key_path));
        }
        TlsMode::MTls => {
            let cert_path = transport_cfg.tls_cert.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls_cert is required for mTLS mode",
                )
            })?;
            let key_path = transport_cfg.tls_key.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls_key is required for mTLS mode",
                )
            })?;
            quic_config.tls_cert_key_paths = Some((cert_path, key_path));
            quic_config.root_ca_path = Some(transport_cfg.ca_cert.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ca_cert is required for mTLS mode",
                )
            })?);
        }
        TlsMode::Insecure => {
            quic_config.enable_self_signed = true;
        }
    }

    let mut transport_config = QuicTransportConfig::default();
    if let Some(timeout) = transport_cfg.idle_timeout {
        transport_config.max_idle_timeout(Duration::from_millis(timeout))?;
    }
    if let Some(interval) = transport_cfg.keep_alive {
        transport_config.keep_alive_period(Duration::from_millis(interval))?;
    }
    if let Some(max_streams) = transport_cfg.max_streams {
        transport_config.max_open_bidirectional_streams(max_streams)?;
    }
    if let Some(congestion) = transport_cfg.congestion {
        transport_config.congestion(congestion, transport_cfg.cwnd_init)?;
    }
    quic_config.transport_config(transport_config);

    let socket = UdpSocket::bind(config.listen)?;
    Ok(QuicServer::new(socket, quic_config).await?)
}
