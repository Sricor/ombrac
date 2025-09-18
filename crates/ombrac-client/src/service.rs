use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

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
        setup_logging(config);

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
                handles.push(start_tun(client, secret, config, shutdown_tx.subscribe()).await?);
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
fn setup_logging(config: &ServiceConfig) {
    let log_level_str = config.logging.log_level.as_deref().unwrap_or("WARN");
    let log_level: tracing::Level = log_level_str.parse().unwrap_or(tracing::Level::WARN);

    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_max_level(log_level);

    let (non_blocking, guard) = if let Some(path) = &config.logging.log_dir {
        let prefix = config
            .logging
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
async fn start_http_server<I: Initiator>(
    ombrac: Arc<Client<I>>,
    secret: Secret,
    address: SocketAddr,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    use crate::endpoint::http::Server as HttpServer;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(address).await?;
    info!("HTTP/HTTPS endpoint listening on {}", address);

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
async fn start_socks_server<I: Initiator>(
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
    info!("SOCKS endpoint listening on {}", address);

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
async fn start_tun<I: Initiator>(
    client: Arc<Client<I>>,
    secret: Secret,
    config: &TunConfig,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    use crate::endpoint::tun::Tun;
    use crate::endpoint::tun::fakedns::FakeDns;

    info!("TUN Start");

    if config.tun_ipv4.is_none() && config.tun_ipv6.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN device must be configured with at least one IPv4 or IPv6 address.",
        ));
    }

    let mut builder = tun_rs::DeviceBuilder::new();
    builder = builder.mtu(config.tun_mtu);
    if let Some(ip) = config.tun_ipv4 {
        builder = builder.ipv4(ip.addr(), ip.netmask(), None);
    }
    if let Some(ip) = config.tun_ipv6 {
        builder = builder.ipv6(ip.addr(), ip.netmask());
    }

    let fakedns = FakeDns::default();
    let fd = builder.build_async()?.into_fd()?;
    let tun = Tun::new(client, secret, fakedns.into());
    let handle = tokio::spawn(async move {
        let shutdown_signal = async {
            let _ = shutdown_rx.recv().await;
        };

        tun.run(fd, shutdown_signal)
            .await
            .expect("SOCKS server failed to run");
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

    let mut addrs: Vec<_> = tokio::net::lookup_host(server).await?.collect();
    if transport_cfg.prefer_ipv6 {
        addrs.sort_by_key(|a| !a.is_ipv6());
    } else if transport_cfg.prefer_ipv4 {
        addrs.sort_by_key(|a| !a.is_ipv4());
    }

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



// Destination        Gateway            Flags               Netif Expire
// default            192.168.31.1       UGScg                 en0       
// 127.0.0.1          127.0.0.1          UH                    lo0       
// 192.168.31         link#6             UCS                   en0      !
// 192.168.31.1/32    link#6             UCS                   en0      !
// 192.168.31.1       a4:a9:30:9c:a8:4f  UHLWIir               en0   1173
// 192.168.31.3/32    link#6             UCS                   en0      !
// 192.168.31.3       5c:1b:f4:8f:86:21  UHLWI                 lo0       
// 192.168.31.5       14:7f:ce:a1:92:20  UHLWIi                en0   1177
// 192.168.31.89      4a:35:a2:8e:65:1a  UHLWIi                en0   1186
// 198.19.0           198.19.0.1         UGSc                  en0       
// 198.19.0.255       198.19.0.1         UH                  utun8       
// 224.0.0/4          link#6             UmCS                  en0      !
// 224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       
// 227.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 228.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 229.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 230.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 232.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 255.255.255.255/32 link#6             UCS                   en0      !



// Destination        Gateway            Flags               Netif Expire
// 0/1                198.19.0.1         UGScg               utun8       
// default            192.168.31.1       UGScg                 en0       
// 3.0.223.235/32     192.168.31.1       UGSc                  en0       
// 10                 192.168.31.1       UGSc                  en0       
// 127                192.168.31.1       UGSc                  en0       
// 127.0.0.1          127.0.0.1          UH                    lo0       
// 128.0/1            198.19.0.1         UGSc                utun8       
// 169.254            192.168.31.1       UGSc                  en0       
// 172.16/12          192.168.31.1       UGSc                  en0       
// 192.168.0/16       192.168.31.1       UGSc                  en0       
// 192.168.31         link#6             UCS                   en0      !
// 192.168.31.1/32    link#6             UCS                   en0      !
// 192.168.31.1       a4:a9:30:9c:a8:4f  UHLWIir               en0   1163
// 192.168.31.3/32    link#6             UCS                   en0      !
// 192.168.31.3       5c:1b:f4:8f:86:21  UHLWIi                lo0       
// 192.168.31.5       14:7f:ce:a1:92:20  UHLWIi                en0   1130
// 192.168.31.89      4a:35:a2:8e:65:1a  UHLWIi                en0   1139
// 198.19.0           198.19.0.1         UGSc                  en0       
// 198.19.0.255       198.19.0.1         UH                  utun8       
// 224.0.0/4          link#6             UmCS                  en0      !
// 224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       
// 227.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 228.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 229.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 230.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 232.18.0.0         1:0:5e:12:0:0      UHmLWI                en0       
// 255.255.255.255/32 link#6             UCS                   en0      !