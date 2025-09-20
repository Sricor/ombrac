use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use ombrac_transport::Unreliable;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use ombrac::Secret;
use ombrac::client::Client;
use ombrac_macros::{error, info, warn};
use ombrac_transport::Initiator;
#[cfg(feature = "transport-quic")]
use ombrac_transport::quic::{
    TransportConfig as QuicTransportConfig,
    client::{Client as QuicClient, Config as QuicConfig},
};

#[cfg(feature = "endpoint-tun")]
use crate::config::TunConfig;
use crate::config::{ServiceConfig, TlsMode};

pub struct Service {
    handles: Vec<JoinHandle<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl Service {
    pub async fn build(config: &ServiceConfig) -> io::Result<Self> {
        #[cfg(feature = "tracing")]
        setup_logging(&config.logging);

        let mut handles = Vec::new();
        let (shutdown_tx, _) = broadcast::channel(1);

        #[cfg(feature = "transport-quic")]
        {
            let secret = *blake3::hash(config.secret.as_bytes()).as_bytes();
            let transport = quic_client_from_config(config).await?;
            let client = Arc::new(Client::new(transport));

            // Start HTTP endpoint if configured
            #[cfg(feature = "endpoint-http")]
            if let Some(address) = config.endpoint.http {
                let handle =
                    start_http_server(client.clone(), secret, address, shutdown_tx.subscribe())
                        .await?;
                handles.push(handle);
            }

            // Start SOCKS endpoint if configured
            #[cfg(feature = "endpoint-socks")]
            if let Some(address) = config.endpoint.socks {
                let handle =
                    start_socks_server(client.clone(), secret, address, shutdown_tx.subscribe())
                        .await?;
                handles.push(handle);
            }

            #[cfg(feature = "endpoint-tun")]
            if let Some(config) = &config.endpoint.tun {
                if config.tun_ipv4.is_some() || config.tun_ipv6.is_some() {
                    let handle =
                        start_tun_device(client, secret, config, shutdown_tx.subscribe()).await?;
                    handles.push(handle);
                }
            }
        }

        Ok(Service {
            handles,
            shutdown_tx,
        })
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());

        for handle in self.handles {
            if let Err(_err) = handle.await {
                error!("A task failed to shut down cleanly: {:?}", _err);
            }
        }
        warn!("Service shutdown complete");
    }
}

#[cfg(feature = "tracing")]
fn setup_logging(config: &crate::config::LoggingConfig) {
    let log_level: tracing::Level = config.log_level.as_deref().unwrap().parse().unwrap();

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

    // The guard must be held for the lifetime of the program to ensure logs are flushed.
    // In a long-running application like this, we can "leak" it to achieve this.
    std::mem::forget(guard);
    subscriber.with_writer(non_blocking).init();
}

#[cfg(feature = "endpoint-http")]
async fn start_http_server<I: Initiator + Unreliable>(
    ombrac: Arc<Client<I>>,
    secret: Secret,
    address: SocketAddr,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    use crate::endpoint::http::Server as HttpServer;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(address).await?;
    info!("Starting HTTP/HTTPS endpoint, listening on {}", address);

    let handle = tokio::spawn(async move {
        let shutdown_signal = async {
            let _ = shutdown_rx.recv().await;
        };
        HttpServer::run(listener, secret, ombrac, shutdown_signal)
            .await
            .expect("HTTP server failed to run");
    });

    Ok(handle)
}

#[cfg(feature = "endpoint-socks")]
async fn start_socks_server<I: Initiator + Unreliable>(
    ombrac: Arc<Client<I>>,
    secret: Secret,
    address: SocketAddr,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    use crate::endpoint::socks::CommandHandler;
    use socks_lib::net::TcpListener;
    use socks_lib::v5::server::auth::NoAuthentication;
    use socks_lib::v5::server::{Config as SocksConfig, Server as SocksServer};

    let listener = TcpListener::bind(address).await?;
    info!("Starting SOCKS5 endpoint, listening on {}", address);

    let handle = tokio::spawn(async move {
        let config = SocksConfig::new(NoAuthentication, CommandHandler::new(ombrac, secret));
        let shutdown_signal = async {
            let _ = shutdown_rx.recv().await;
        };
        SocksServer::run(listener, config.into(), shutdown_signal)
            .await
            .expect("SOCKS server failed to run");
    });

    Ok(handle)
}

#[cfg(feature = "endpoint-tun")]
async fn start_tun_device<I: Initiator + Unreliable>(
    client: Arc<Client<I>>,
    secret: Secret,
    config: &TunConfig,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    use crate::endpoint::tun::Tun;
    use crate::endpoint::tun::fakedns::FakeDns;
    use ipnet::{Ipv4Net, Ipv6Net};
    use std::str::FromStr;

    let fakedns = {
        let dns_pool = Ipv4Net::from_str(
            config
                .dns_pool
                .clone()
                .unwrap_or("198.18.0.0/16".to_string())
                .as_str(),
        )
        .unwrap();
        FakeDns::new(dns_pool.addr(), dns_pool.prefix_len())
    };

    let device = {
        let mut builder = tun_rs::DeviceBuilder::new();
        builder = builder.mtu(config.tun_mtu.unwrap_or(1500));
        if let Some(ip_str) = &config.tun_ipv4 {
            let ip = Ipv4Net::from_str(&ip_str).unwrap();
            builder = builder.ipv4(ip.addr(), ip.netmask(), None);
        }
        if let Some(ip_str) = &config.tun_ipv6 {
            let ip = Ipv6Net::from_str(&ip_str).unwrap();
            builder = builder.ipv6(ip.addr(), ip.netmask());
        }
        builder.build_async()?
    };

    info!(
        "Starting TUN endpoint, Name: {}, MTU: {}, IP: {:?}",
        device.name()?,
        device.mtu()?,
        device.addresses()?
    );

    let fd = device.into_fd()?;
    let tun = Tun::new(client, secret, fakedns.into());
    let handle = tokio::spawn(async move {
        let shutdown_signal = async {
            let _ = shutdown_rx.recv().await;
        };

        tun.run(fd, shutdown_signal)
            .await
            .expect("TUN device failed to run");
    });

    Ok(handle)
}

#[cfg(feature = "transport-quic")]
async fn quic_client_from_config(config: &ServiceConfig) -> io::Result<QuicClient> {
    let server = &config.server;
    let transport_cfg = &config.transport;

    let server_name = match &transport_cfg.server_name {
        Some(value) => value.clone(),
        None => {
            let pos = server.rfind(':').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid server address: {}", server),
                )
            })?;
            server[..pos].to_string()
        }
    };

    let addrs: Vec<_> = tokio::net::lookup_host(server).await?.collect();
    let server_addr = addrs.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to resolve server address: '{}'", server),
        )
    })?;

    let bind_addr = transport_cfg.bind.unwrap_or_else(|| match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0),
    });

    let mut quic_config = QuicConfig::new(server_addr, server_name);

    quic_config.enable_zero_rtt = transport_cfg.zero_rtt.unwrap_or(false);
    if let Some(protocols) = &transport_cfg.alpn_protocols {
        quic_config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
    }

    match transport_cfg.tls_mode.unwrap_or(TlsMode::Tls) {
        TlsMode::Tls => {
            if let Some(ca) = &transport_cfg.ca_cert {
                quic_config.root_ca_path = Some(ca.to_path_buf());
            }
        }
        TlsMode::MTls => {
            quic_config.root_ca_path = Some(transport_cfg.ca_cert.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CA cert is required for mTLS mode",
                )
            })?);
            let client_cert = transport_cfg.client_cert.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Client cert is required for mTLS mode",
                )
            })?;
            let client_key = transport_cfg.client_key.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Client key is required for mTLS mode",
                )
            })?;
            quic_config.client_cert_key_paths = Some((client_cert, client_key));
        }
        TlsMode::Insecure => {
            quic_config.skip_server_verification = true;
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

    let socket = UdpSocket::bind(bind_addr)?;
    Ok(QuicClient::new(quic_config, socket).await?)
}
