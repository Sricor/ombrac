use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_channel::{Receiver, Sender};
use ombrac_macros::{debug, error, info, warn};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::quic::TransportConfig;
use crate::quic::protocol::{decode_addr, encode_addr};
use crate::quic::stream::Stream;
use crate::{Acceptor, Reliable};

use super::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub enable_zero_rtt: bool,
    pub enable_self_signed: bool,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub root_ca_path: Option<PathBuf>,
    pub tls_cert_key_paths: Option<(PathBuf, PathBuf)>,

    transport_config: Arc<quinn::TransportConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            tls_cert_key_paths: None,
            root_ca_path: None,
            enable_zero_rtt: false,
            enable_self_signed: false,
            alpn_protocols: Vec::new(),
            transport_config: Arc::new(quinn::TransportConfig::default()),
        }
    }

    pub fn transport_config(&mut self, config: TransportConfig) {
        self.transport_config = Arc::new(config.0)
    }

    fn build_endpoint_config(&self) -> Result<quinn::EndpointConfig> {
        Ok(quinn::EndpointConfig::default())
    }

    fn build_server_config(&self) -> Result<quinn::ServerConfig> {
        use quinn::crypto::rustls::QuicServerConfig;

        let server_crypto = self.build_tls_config()?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

        server_config.transport_config(self.transport_config.clone());

        Ok(server_config)
    }

    fn build_tls_config(&self) -> Result<rustls::ServerConfig> {
        let (certs, key) = if self.enable_self_signed {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
            let certs = vec![CertificateDer::from(cert.cert)];
            (certs, key)
        } else {
            let (cert, key) = self
                .tls_cert_key_paths
                .as_ref()
                .ok_or(Error::ServerMissingCertificate)?;
            let certs = super::load_certificates(cert)?;
            let key = super::load_private_key(key)?;
            (certs, key)
        };

        let config_builder = rustls::ServerConfig::builder();

        let mut tls_config = if let Some(ca_path) = &self.root_ca_path {
            // Enable mTLS, Client auth
            let mut ca_store = rustls::RootCertStore::empty();
            let ca_certs = super::load_certificates(ca_path)?;
            ca_store.add_parsable_certificates(ca_certs);

            let verifier = rustls::server::WebPkiClientVerifier::builder(ca_store.into())
                .build()
                .map_err(io::Error::other)?;

            config_builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        } else {
            config_builder
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };

        tls_config.alpn_protocols = self.alpn_protocols.clone();

        if self.enable_zero_rtt {
            tls_config.send_half_rtt_data = true;
            tls_config.max_early_data_size = u32::MAX;
        }

        Ok(tls_config)
    }
}

const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct Server {
    endpoint: Arc<quinn::Endpoint>,
    stream_receiver: Receiver<Stream>,
    shutdown_sender: watch::Sender<()>,
}

impl Server {
    pub async fn new(config: Config, socket: std::net::UdpSocket) -> Result<Self> {
        let server_config = config.build_server_config()?;
        let endpoint_config = config.build_endpoint_config()?;

        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("No async runtime found"))?;
        let endpoint = Arc::new(quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )?);

        let (stream_sender, stream_receiver) = async_channel::unbounded();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());

        tokio::spawn(run(endpoint.clone(), stream_sender, shutdown_receiver));

        Ok(Self {
            endpoint,
            stream_receiver,
            shutdown_sender,
        })
    }

    /// Signals the server to stop accepting new connections and shutdown gracefully.
    pub fn shutdown(&self) {
        let _ = self.shutdown_sender.send(());
    }

    pub async fn accept_bidirectional(&self) -> Result<Stream> {
        match self.stream_receiver.recv().await {
            Ok(value) => Ok(value),
            Err(_) => Err(Error::ConnectionClosed),
        }
    }

    /// Closes all connections immediately and stops accepting new ones.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"Server closed");
    }

    /// Get the local SocketAddr the underlying socket is bound to
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Switch to a new UDP socket
    pub fn rebind(&self, socket: std::net::UdpSocket) -> Result<()> {
        Ok(self.endpoint.rebind(socket)?)
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await
    }
}

async fn run(
    endpoint: Arc<quinn::Endpoint>,
    stream_sender: Sender<Stream>,
    mut shutdown_receiver: watch::Receiver<()>,
) {
    loop {
        let stream_sender = stream_sender.clone();
        let endpoint = endpoint.clone();

        tokio::select! {
            Some(conn) = endpoint.accept() => {
                tokio::spawn(async move {
                    match conn.await {
                        Ok(new_connection) => {
                            info!("New connection from: {}", new_connection.remote_address());
                            let connection = Arc::new(new_connection);

                            tokio::spawn(handle_full_cone_proxy(connection.clone()));

                            loop {
                                tokio::select! {
                                    Ok((send, recv)) = connection.accept_bi() => {
                                        if stream_sender.send(Stream(send, recv)).await.is_err() {
                                            error!("Stream receiver dropped, cannot accept new streams");
                                            break;
                                        }
                                    }
                                    else => {
                                        debug!("Connection handling loop finished for {}", connection.remote_address());
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_err) => {
                            error!("Connection error: {}", _err);
                        }
                    }
                });
            }
            _ = shutdown_receiver.changed() => {
                endpoint.close(0u32.into(), b"Server shutting down");
                break;
            }
        }
    }
}

async fn handle_full_cone_proxy(conn: Arc<quinn::Connection>) {
    // 1. 创建专用的 UDP 套接字
    let proxy_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to bind UDP socket for proxy: {}", e);
            conn.close(1u32.into(), b"Internal Server Error");
            return;
        }
    };
    info!(
        "Created UDP proxy socket at {} for client {}",
        proxy_socket.local_addr().unwrap(),
        conn.remote_address()
    );

    // 2. 启动两个任务进行双向数据转发
    // 任务1: 从 QUIC 读取数据报, 解码目标地址, 然后通过 UDP 套接字发送出去
    let fwd_conn = conn.clone();
    let fwd_socket = proxy_socket.clone();
    let fwd_task = tokio::spawn(async move {
        loop {
            match fwd_conn.read_datagram().await {
                Ok(datagram) => {
                    if let Some((dest_addr, payload)) = decode_addr(&datagram) {
                        info!("Server Read Datagram dest: {}, playload: {}", dest_addr, payload.len());
                        if let Err(e) = fwd_socket.send_to(payload, dest_addr).await {
                            warn!("Failed to send UDP packet to {}: {}", dest_addr, e);
                        }
                    } else {
                        warn!(
                            "Received invalid datagram from client {}",
                            fwd_conn.remote_address()
                        );
                    }
                }
                Err(e) => {
                    debug!("QUIC datagram read error (connection closing?): {}", e);
                    break;
                }
            }
        }
    });

    // 任务2: 从 UDP 套接字读取数据, 编码源地址, 然后通过 QUIC 数据报发回客户端
    let bwd_conn = conn.clone();
    let bwd_socket = proxy_socket.clone();
    let bwd_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        loop {
            match bwd_socket.recv_from(&mut buf).await {
                Ok((len, source_addr)) => {
                    let payload = &buf[..len];
                    let mut response_datagram = encode_addr(&source_addr);
                    response_datagram.extend_from_slice(payload);

                    info!("Server Send Datagram dest: {}, playload: {}", source_addr, payload.len());

                    if let Err(e) = bwd_conn.send_datagram(response_datagram.into()) {
                        debug!("Failed to send QUIC datagram (connection closing?): {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("UDP socket recv_from error: {}", e);
                    break;
                }
            }
        }
    });

    // 等待任一任务结束. 如果一个方向的转发停止 (通常是由于QUIC连接断开), 我们就清理所有资源.
    tokio::select! {
        _ = fwd_task => {},
        _ = bwd_task => {},
    }

    info!("Closing UDP proxy for client {}", conn.remote_address());
}

impl Acceptor for Server {
    async fn accept_bidirectional(&self) -> io::Result<impl Reliable> {
        Ok(Server::accept_bidirectional(self).await?)
    }
}
