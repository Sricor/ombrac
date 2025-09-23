use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures::StreamExt;
use moka::future::Cache;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_util::{codec::Framed, sync::CancellationToken};

use ombrac::{
    protocol::{Address, PROTOCOLS_VERSION, Secret, UdpPacket},
    reassembly::UdpReassembler,
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
                    if let Ok(connection) = accepted {
                        let secret = self.secret;
                        let peer_addr = connection.remote_address().unwrap_or_else(|_| "unknown".parse().unwrap());
                        tokio::spawn(async move {
                            info!("{} Accepted new connection", peer_addr);
                            if let Err(e) = Self::handle_connection(connection, secret, peer_addr).await {
                                error!("{} Connection handler failed: {}", peer_addr, e);
                            }
                        });
                    } else if let Err(e) = accepted {
                        error!("Failed to accept connection: {}", e);
                    }
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

        match framed_control.next().await {
            Some(Ok(UpstreamMessage::Hello(hello))) => {
                if hello.version != PROTOCOLS_VERSION {
                    let err = "Unsupported protocol version";
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err));
                }
                if hello.secret != secret {
                    let err = "Invalid secret";
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, err));
                }
                debug!("{} Client handshake successful", peer_addr);
            }
            _ => {
                let err = "Expected Hello message";
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        }

        let connection = Arc::new(connection);
        let cancellation_token = CancellationToken::new();

        let tcp_handler = Self::spawn_tcp_handler(
            Arc::clone(&connection),
            peer_addr,
            cancellation_token.child_token(),
        );
        let udp_handler = Self::spawn_udp_handler(
            Arc::clone(&connection),
            peer_addr,
            cancellation_token.child_token(),
        );

        let result = tokio::try_join!(tcp_handler, udp_handler);

        // Signal all tasks to shut down.
        cancellation_token.cancel();

        match result {
            Ok(_) => {
                debug!("{} Client connection closed gracefully.", peer_addr);
            }
            Err(e) => {
                warn!(
                    "{} Client connection closed with an error: {}",
                    peer_addr, e
                )
            }
        }

        Ok(())
    }

    fn spawn_tcp_handler(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        token: CancellationToken,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        return Ok(());
                    }
                    result = connection.accept_bidirectional() => {
                        let stream = result?;
                        info!("{} Accepted new bidirectional stream for TCP", peer_addr);

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_tcp_stream_task(stream, peer_addr).await {
                                warn!("{} TCP stream handler error: {}", peer_addr, e);
                            }
                        });
                    }
                }
            }
        })
    }

    async fn handle_tcp_stream_task(
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
        token: CancellationToken,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move { Self::handle_udp_session(connection, peer_addr, token).await })
    }

    async fn handle_udp_session(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        token: CancellationToken,
    ) -> io::Result<()> {
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);
        let udp_socket = Arc::new(UdpSocket::bind("[::]:0").await?);
        info!(
            "{} UDP proxy socket bound to: {}",
            peer_addr,
            udp_socket.local_addr()?
        );

        let reassembler = UdpReassembler::default();
        let fragment_id_counter = Arc::new(AtomicU16::new(0));
        let dns_cache: Cache<Bytes, SocketAddr> = Cache::builder()
            .time_to_live(Duration::from_secs(300))
            .build();

        let upstream_conn = Arc::clone(&connection);
        let upstream_sock = Arc::clone(&udp_socket);
        let upstream_cache = dns_cache.clone();
        let upstream_handler = tokio::spawn(async move {
            loop {
                let packet_bytes = upstream_conn.read_datagram().await?;
                let packet = UdpPacket::decode(packet_bytes)?;

                if let Some((address, data)) = reassembler.process(packet)? {
                    match address {
                        Address::SocketV4(addr) => {
                            upstream_sock.send_to(&data, addr).await?;
                        }
                        Address::SocketV6(addr) => {
                            upstream_sock.send_to(&data, addr).await?;
                        }
                        Address::Domain(domain, port) => {
                            let result = upstream_cache
                                .try_get_with(domain.clone(), async {
                                    let domain_str = String::from_utf8_lossy(&domain);
                                    let addr_str = format!("{}:{}", domain_str, port);
                                    tokio::net::lookup_host(&addr_str).await?.next().ok_or_else(
                                        || {
                                            io::Error::new(
                                                io::ErrorKind::NotFound,
                                                "DNS resolution failed",
                                            )
                                        },
                                    )
                                })
                                .await;

                            match result {
                                Ok(addr) => {
                                    if let Err(e) = upstream_sock.send_to(&data, addr).await {
                                        warn!(
                                            "{} Failed to send UDP packet to {}: {}",
                                            peer_addr, addr, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "{} UDP DNS resolution failed for domain '{}': {}",
                                        peer_addr,
                                        String::from_utf8_lossy(&domain),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        let downstream_conn = Arc::clone(&connection);
        let downstream_sock = Arc::clone(&udp_socket);
        let downstream_handler = tokio::spawn(async move {
            let mut buf = vec![0u8; max_datagram_size];
            loop {
                let (len, from_addr) = downstream_sock.recv_from(&mut buf).await?;
                let data = Bytes::copy_from_slice(&buf[..len]);
                let address = Address::from(from_addr);

                let overhead = 1 + address.encoded_len();
                let predicted_len = overhead + data.len();

                if predicted_len <= max_datagram_size {
                    let unfragmented_packet = UdpPacket::Unfragmented { address, data };
                    downstream_conn
                        .send_datagram(unfragmented_packet.encode()?)
                        .await?;
                } else {
                    warn!(
                        "UDP packet from {} is too large (predicted size {} > max {}), splitting...",
                        from_addr, predicted_len, max_datagram_size
                    );

                    let fragment_id = fragment_id_counter.fetch_add(1, Ordering::Relaxed);
                    let fragments =
                        UdpPacket::split_packet(address, data, max_datagram_size, fragment_id);

                    let mut fragments = fragments.peekable();
                    if fragments.peek().is_none() {
                        error!(
                            "Packet from {} is too large to be fragmented and sent",
                            from_addr
                        );
                        continue;
                    }

                    for fragment in fragments {
                        downstream_conn.send_datagram(fragment.encode()?).await?;
                    }
                }
            }
        });

        // Race the handlers against the cancellation token.
        tokio::select! {
            res = upstream_handler => res.unwrap_or(Ok(())),
            res = downstream_handler => res.unwrap_or(Ok(())),
            _ = token.cancelled() => {
                debug!("{} UDP handler received cancellation signal.", peer_addr);
                Ok(())
            }
        }
    }
}
