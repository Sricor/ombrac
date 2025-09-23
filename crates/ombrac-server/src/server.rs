// server.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::{io, net::SocketAddr};

use bytes::Bytes;
use futures::StreamExt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_util::codec::Framed;

use ombrac::{
    protocol::{Address, PROTOCOLS_VERSION, Secret, UdpPacket},
    reassembly::UdpReassembler, // 引入 UdpReassembler
    upstream::{ProtocolCodec, UpstreamMessage},
};
use ombrac_macros::{debug, error, info, warn};
use ombrac_transport::{Acceptor, Connection};

pub struct Server<T: Acceptor> {
    acceptor: Arc<T>,
    secret: Secret,
}

impl<T: Acceptor> Server<T> {
    pub fn new(acceptor: T, secret: Secret) -> Self {
        Self {
            acceptor: Arc::new(acceptor),
            secret,
        }
    }

    pub async fn accept_loop(&self, mut shutdown_rx: broadcast::Receiver<()>) -> io::Result<()> {
        info!(
            "Server is running, listening on {}",
            self.acceptor.local_addr()?
        );

        loop {
            tokio::select! {
                accepted = self.acceptor.accept() => {
                    let secret = self.secret;

                    tokio::spawn(async move {
                        let connection = accepted.unwrap();
                        let peer_addr = connection.remote_address().unwrap();
                        info!("{} Accepted new connection", peer_addr);

                        if let Err(e) = Self::handle_connection(connection, secret, peer_addr).await {
                            error!("{} Failed to handle connection: {}", peer_addr, e);
                        }
                    });
                },

                _ = shutdown_rx.recv() => {
                    debug!("Shutdown signal received, stopping accept loop.");
                    return Ok(());
                }
            }
        }
    }

    async fn handle_connection(
        connection: T::Connection,
        secret: Secret,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let mut control_stream = connection.accept_bidirectional().await?;
        let mut framed_control = Framed::new(&mut control_stream, ProtocolCodec);

        // ClientHello
        match framed_control.next().await {
            Some(Ok(UpstreamMessage::Hello(hello))) => {
                if hello.version != PROTOCOLS_VERSION {
                    let err = "Unsupported protocol version";
                    error!("{} Handshake failed: {}", peer_addr, err);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err));
                }
                if hello.secret != secret {
                    let err = "Invalid secret";
                    error!("{} Handshake failed: {}", peer_addr, err);
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, err));
                }
                debug!("{} Client handshake successful", peer_addr);
            }
            _ => {
                let err = "Expected Hello message";
                error!("{} Handshake failed: {}", peer_addr, err);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        }

        let connection = Arc::new(connection);
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);

        let tcp_handler = Self::spawn_tcp_handler(Arc::clone(&connection), peer_addr);
        let udp_handler =
            Self::spawn_udp_handler(Arc::clone(&connection), peer_addr, max_datagram_size);

        let _ = tokio::try_join!(tcp_handler, udp_handler);

        debug!("{} Client connection closed.", peer_addr);
        Ok(())
    }

    fn spawn_tcp_handler(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            loop {
                let stream = connection.accept_bidirectional().await?;
                info!("{} Accepted new bidirectional stream for TCP", peer_addr);

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_tcp_stream(stream, peer_addr).await {
                        error!("{} TCP stream handler error: {}", peer_addr, e);
                    }
                });
            }
        })
    }

    async fn handle_tcp_stream(
        mut stream: <T::Connection as Connection>::Stream,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        let mut framed = Framed::new(&mut stream, ProtocolCodec);

        let dest_addr = match framed.next().await {
            Some(Ok(UpstreamMessage::Connect(connect))) => connect.address,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected Connect message on new stream",
                ));
            }
        };

        info!("{} Received proxy request to: {}", peer_addr, dest_addr);

        let mut dest_stream = match dest_addr {
            Address::SocketV4(addr) => TcpStream::connect(addr).await?,
            Address::SocketV6(addr) => TcpStream::connect(addr).await?,
            Address::Domain(_, _) => TcpStream::connect(dest_addr.to_string()).await?,
        };

        info!(
            "{} Successfully connected to destination: {}",
            peer_addr, dest_addr
        );

        let parts = framed.into_parts();
        let mut stream = parts.io;
        let leftover_bytes = parts.read_buf;
        if !leftover_bytes.is_empty() {
            dest_stream.write_all(&leftover_bytes).await?;
        }

        let (up, down) =
            ombrac_transport::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        info!(
            "{} Proxy to {} finished. Upstream: {} bytes, Downstream: {} bytes",
            peer_addr, dest_addr, up, down
        );

        Ok(())
    }

    fn spawn_udp_handler(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        max_datagram_size: usize,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("[::]:0").await?;
            let udp_socket = Arc::new(udp_socket);
            info!(
                "{} UDP proxy socket bound to: {}",
                peer_addr,
                udp_socket.local_addr()?
            );

            // [新增] 为此连接会话创建重组器和分片ID计数器
            let reassembler = UdpReassembler::new();
            let fragment_id_counter = Arc::new(AtomicU16::new(0));

            // Upstream: 从客户端接收数据，发往互联网 (接收端 -> 需要重组)
            let upstream_conn = Arc::clone(&connection);
            let upstream_sock = Arc::clone(&udp_socket);
            let upstream_handler = tokio::spawn(async move {
                loop {
                    let packet_bytes = upstream_conn.read_datagram().await?;
                    let packet = UdpPacket::decode(packet_bytes)?;

                    // [修正] 将包交给重组器处理
                    if let Some((address, data)) = reassembler.process(packet)? {
                        // 得到一个完整的包后，再发送
                        match address {
                            Address::SocketV4(addr) => {
                                upstream_sock.send_to(&data, addr).await?;
                            }
                            Address::SocketV6(addr) => {
                                upstream_sock.send_to(&data, addr).await?;
                            }
                            Address::Domain(_, _) => {
                                let dest_addr_str = address.to_string();
                                match tokio::net::lookup_host(&dest_addr_str).await?.next() {
                                    Some(addr) => {
                                        upstream_sock.send_to(&data, addr).await?;
                                    }
                                    None => {
                                        error!("UDP DNS resolution failed for: {}", dest_addr_str);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    // 如果是分片，reassembler.process 会返回 Ok(None)，循环继续
                }
            });

            // Downstream: 从互联网接收数据，发往客户端 (发送端 -> 需要分片)
            let downstream_conn = Arc::clone(&connection);
            let downstream_sock = Arc::clone(&udp_socket);
            let downstream_handler = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535]; // 从socket可以读到最大UDP包
                loop {
                    let (len, from_addr) = downstream_sock.recv_from(&mut buf).await?;
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    let address = Address::from(from_addr);

                    // [修正] 检查是否需要分片
                    let unfragmented_packet = UdpPacket::Unfragmented {
                        address: address.clone(),
                        data: data.clone(),
                    };
                    let encoded = unfragmented_packet.encode();

                    if encoded.len() <= max_datagram_size {
                        downstream_conn.send_datagram(encoded).await?;
                    } else {
                        warn!(
                            "UDP packet from {} is too large ({} bytes), splitting...",
                            from_addr,
                            data.len()
                        );
                        let fragment_id = fragment_id_counter.fetch_add(1, Ordering::Relaxed);
                        let fragments =
                            UdpPacket::split_packet(address, data, max_datagram_size, fragment_id);

                        if fragments.is_empty() {
                            error!(
                                "Packet from {} is too large to be fragmented and sent",
                                from_addr
                            );
                            continue;
                        }

                        for fragment in fragments {
                            downstream_conn.send_datagram(fragment.encode()).await?;
                        }
                    }
                }
            });

            tokio::select! {
                res = upstream_handler => res.unwrap_or(Ok(())),
                res = downstream_handler => res.unwrap_or(Ok(())),
            }
        })
    }
}
