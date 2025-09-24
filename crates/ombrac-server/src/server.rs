use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

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
    protocol::{self, Address, PROTOCOLS_VERSION, Secret, UdpPacket},
    reassembly::UdpReassembler, // Added missing import
    upstream::{UpstreamMessage, new_codec},
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
                                // Avoid logging "Connection reset by peer" as an error, it's common.
                                if e.kind() != io::ErrorKind::ConnectionReset && e.kind() != io::ErrorKind::BrokenPipe {
                                    error!("{} Connection handler failed: {}", peer_addr, e);
                                } else {
                                    info!("{} Connection closed by peer.", peer_addr);
                                }
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

        let mut framed_control = Framed::new(&mut control_stream, new_codec());

        match framed_control.next().await {
            Some(Ok(payload)) => {
                // FIXED: Use our protocol helper to decode the message correctly
                let hello_message: UpstreamMessage = protocol::decode(&payload)?;

                if let UpstreamMessage::Hello(hello) = hello_message {
                    if hello.version != PROTOCOLS_VERSION {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Unsupported protocol version",
                        ));
                    }
                    if hello.secret != secret {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Invalid secret",
                        ));
                    }
                    debug!("{} Client handshake successful", peer_addr);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected Hello message",
                    ));
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to read Hello message",
                ));
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

        // Wait for either handler to fail or the connection to close.
        let result = tokio::select! {
            res = tcp_handler => res,
            res = udp_handler => res,
        };

        cancellation_token.cancel();

        match result {
            Ok(Ok(_)) => {
                debug!("{} Client connection closed gracefully.", peer_addr);
            }
            Ok(Err(e)) => {
                warn!(
                    "{} Client connection closed with an error: {}",
                    peer_addr, e
                );
            }
            Err(e) => {
                warn!(
                    "{} Client connection closed with an error: {}",
                    peer_addr, e
                );
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
        let mut framed = Framed::new(&mut stream, new_codec());

        let dest_addr = match framed.next().await {
            Some(Ok(payload)) => {
                let message: UpstreamMessage = protocol::decode(&payload)?;
                if let UpstreamMessage::Connect(connect) = message {
                    connect.address
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected Connect message, got something else",
                    ));
                }
            }
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
        tokio::spawn(async move { Self::handle_udp_proxy(connection, peer_addr, token).await })
    }

    /// Handles all UDP proxying for a single client connection.
    /// It creates a dedicated UDP socket for each unique session ID.
    async fn handle_udp_proxy(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        token: CancellationToken,
    ) -> io::Result<()> {
        // Cache to map a client's session_id to its dedicated remote UDP socket.
        // Arc<UdpSocket> allows sharing the socket between the upstream and downstream tasks.
        let session_sockets: Cache<u64, Arc<UdpSocket>> = Cache::builder()
            .time_to_idle(Duration::from_secs(120))
            .eviction_listener(|_key, _val, cause| {
                debug!("UDP session socket evicted due to: {:?}", cause);
            })
            .build();

        let reassembler = Arc::new(UdpReassembler::default());
        let fragment_id_counter = Arc::new(AtomicU16::new(0));

        // Upstream loop: Reads from the client connection, and forwards to the remote destination.
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    debug!("{} UDP proxy handler shutting down.", peer_addr);
                    break;
                }
                result = connection.read_datagram() => {
                    let packet_bytes = match result {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            // The main connection has an error, so we should exit.
                            info!("{} Error reading datagram from client connection: {}. Closing UDP handler.", peer_addr, e);
                            return Err(e);
                        }
                    };

                    debug!(
                        "{} UDP Proxy: Received {} bytes from client connection.",
                        peer_addr, packet_bytes.len()
                    );

                    // FIXED: Use the implemented UdpPacket::decode method
                    let packet = match UdpPacket::decode(packet_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("{} Failed to decode UDP packet from client: {}", peer_addr, e);
                            continue;
                        }
                    };

                    if let Some((session_id, address, data)) = reassembler.process(packet).await? {
                        // Check if a socket for this session already exists.
                        // If not, create a new one.
                        let remote_socket = if let Some(socket) = session_sockets.get(&session_id).await {
                            debug!("{} UDP Proxy [{}]: Reusing existing UDP socket.", peer_addr, session_id);
                            socket
                        } else {
                            // Create a new dedicated UDP socket for this session.
                            let new_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                            session_sockets.insert(session_id, Arc::clone(&new_socket)).await;
                            info!(
                                "{} UDP Proxy [{}]: NEW UDP session created, listening on {}",
                                peer_addr, session_id, new_socket.local_addr()?
                            );

                            // Spawn a dedicated downstream task for this new socket.
                            // This task will read replies from the remote and send them back to the client.
                            let downstream_conn = Arc::clone(&connection);
                            let downstream_sock = Arc::clone(&new_socket);
                            let downstream_token = token.child_token();
                            let downstream_frag_counter = Arc::clone(&fragment_id_counter);

                            tokio::spawn(async move {
                                Self::run_downstream_task(
                                    downstream_conn,
                                    peer_addr,
                                    session_id,
                                    downstream_sock,
                                    downstream_frag_counter,
                                    downstream_token
                                ).await;
                                info!("{} UDP downstream task for session {} finished.", peer_addr, session_id);
                            });
                            new_socket
                        };

                        // Resolve domain name if necessary.
                         let dest_addr = match address.clone() { // Clone address to avoid move issues
                             Address::SocketV4(addr) => SocketAddr::V4(addr),
                             Address::SocketV6(addr) => SocketAddr::V6(addr),
                             Address::Domain(_, _) => {
                                 let addr_str = address.to_string();
                                 match tokio::net::lookup_host(&addr_str).await?.next() {
                                     Some(addr) => addr,
                                     None => {
                                         warn!("{} UDP: DNS resolution failed for {}", peer_addr, addr_str);
                                         continue;
                                     }
                                 }
                             }
                        };

                        debug!(
                            "{} UDP Proxy [{}]: Forwarding {} bytes to destination {}",
                            peer_addr, session_id, data.len(), dest_addr
                        );
                        if let Err(e) = remote_socket.send_to(&data, dest_addr).await {
                             warn!("{} UDP: Failed to send packet to {}: {}", peer_addr, dest_addr, e);
                        }
                    } else {
                        debug!("{} UDP Proxy: Received a fragment, waiting for more parts.", peer_addr);
                    }
                }
            }
        }
        Ok(())
    }

    /// A dedicated task that reads from a single UDP socket (for a single session)
    /// and sends any received data back to the client.
    async fn run_downstream_task(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        session_id: u64,
        socket: Arc<UdpSocket>,
        fragment_id_counter: Arc<AtomicU16>,
        token: CancellationToken,
    ) {
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);
        let mut buf = vec![0u8; 65535];

        // A reasonable guess for payload size, leaving room for headers.
        let max_payload_size = max_datagram_size.saturating_sub(128);

        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                result = socket.recv_from(&mut buf) => {
                    let (len, from_addr) = match result {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("{} UDP: Error receiving from remote socket for session {}: {}", peer_addr, session_id, e);
                            break;
                        }
                    };
                    info!(
                        "{} UDP Downstream [{}]: Received {} bytes from remote {}",
                        peer_addr, session_id, len, from_addr
                    );
                    let data = Bytes::copy_from_slice(&buf[..len]);
                    let address = Address::from(from_addr);

                    // Send back to client, fragmenting if necessary
                    if data.len() <= max_payload_size {
                        let packet = UdpPacket::Unfragmented { session_id, address, data };
                        // FIXED: Use the implemented UdpPacket::encode method
                        if let Ok(encoded) = packet.encode() {
                            debug!(
                                "{} UDP Downstream [{}]: Sending UNFRAGMENTED response ({} bytes) back to client.",
                                peer_addr, session_id, encoded.len()
                            );
                            if connection.send_datagram(encoded).await.is_err() { break; }
                        }
                    } else {
                        warn!(
                            "{} UDP Downstream [{}]: Response packet from {} is too large ({} bytes), splitting...",
                            peer_addr, session_id, from_addr, len
                        );
                        let fragment_id = fragment_id_counter.fetch_add(1, Ordering::Relaxed);
                        // FIXED: Use the implemented UdpPacket::split_packet method
                        let fragments = UdpPacket::split_packet(session_id, address, data, max_payload_size, fragment_id);
                        for (i, fragment) in fragments.enumerate() {
                             // FIXED: Use the implemented UdpPacket::encode method
                            if let Ok(encoded) = fragment.encode() {
                                debug!(
                                    "{} UDP Downstream [{}]: Sending FRAGMENT #{} (frag_id: {}) of response ({} bytes) back to client.",
                                    peer_addr, session_id, i, fragment_id, encoded.len()
                                );
                                if connection.send_datagram(encoded).await.is_err() { break; }
                            }
                        }
                    }
                }
            }
        }
    }
}
