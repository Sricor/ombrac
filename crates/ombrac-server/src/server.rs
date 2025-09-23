use std::io;
use std::marker::PhantomData;
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
    protocol::{Address, PROTOCOLS_VERSION, Secret, UdpPacket},
    reassembly::UdpReassembler,
    upstream::{ProtocolCodec, UpstreamMessage},
};
use ombrac_macros::{debug, error, info, warn};
use ombrac_transport::{Acceptor, Connection};

type UdpSessionCache<C> = Cache<u64, Arc<UdpSession<C>>>;

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
        };

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
        tokio::spawn(
            async move { Self::handle_udp_multiplexing(connection, peer_addr, token).await },
        )
    }

    async fn handle_udp_multiplexing(
        connection: Arc<T::Connection>,
        peer_addr: SocketAddr,
        token: CancellationToken,
    ) -> io::Result<()> {
        let reassembler = UdpReassembler::default();
        let sessions: UdpSessionCache<T::Connection> = Cache::builder()
            .time_to_idle(Duration::from_secs(120))
            .eviction_listener(
                move |_key, session: Arc<UdpSession<<T as Acceptor>::Connection>>, cause| {
                    info!(
                        "UDP session {} for {} evicted due to {:?}, shutting down.",
                        session.id, peer_addr, cause
                    );
                    session.shutdown();
                },
            )
            .build();

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    debug!("{} UDP multiplexer received cancellation signal.", peer_addr);
                    return Ok(());
                }
                result = connection.read_datagram() => {
                    let packet_bytes = result?;
                    let packet = match UdpPacket::decode(packet_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("{} Failed to decode UDP packet: {}", peer_addr, e);
                            continue;
                        }
                    };

                    if let Some((session_id, address, data)) = reassembler.process(packet).await? {
                        let session = sessions.try_get_with(session_id, async {
                            UdpSession::new(session_id, Arc::clone(&connection), peer_addr)
                                .await
                                .map_err(|e| {
                                    error!("Failed to create new UDP session {}: {}", session_id, e);
                                    e
                                })
                        }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                        if let Err(e) = session.send_to_remote(address, data).await {
                             warn!("{} Failed to send UDP packet for session {}: {}", peer_addr, session_id, e);
                        }
                    }
                }
            }
        }
    }
}

/// Represents a single UDP association/session.
struct UdpSession<C: Connection> {
    id: u64,
    socket: Arc<UdpSocket>,
    token: CancellationToken,
    _downstream_task: JoinHandle<()>,
    connection: PhantomData<C>,
}

impl<C: Connection + 'static> UdpSession<C> {
    async fn new(id: u64, connection: Arc<C>, peer_addr: SocketAddr) -> io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        info!(
            "{} New UDP session {} bound to {}",
            peer_addr,
            id,
            socket.local_addr()?
        );
        let token = CancellationToken::new();

        let downstream_task = tokio::spawn(Self::run_downstream_loop(
            id,
            connection,
            Arc::clone(&socket),
            token.child_token(),
            peer_addr,
        ));

        Ok(Arc::new(Self {
            id,
            socket,
            token,
            _downstream_task: downstream_task,
            connection: PhantomData,
        }))
    }

    /// Sends a packet from the client to the remote destination.
    async fn send_to_remote(&self, address: Address, data: Bytes) -> io::Result<()> {
        let dest_addr = match address {
            Address::SocketV4(addr) => SocketAddr::V4(addr),
            Address::SocketV6(addr) => SocketAddr::V6(addr),
            Address::Domain(_, _) => {
                let addr_str = address.to_string();
                tokio::net::lookup_host(addr_str)
                    .await?
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Domain not found"))?
            }
        };
        self.socket.send_to(&data, dest_addr).await?;
        Ok(())
    }

    /// The loop that reads from the remote and sends back to the client.
    async fn run_downstream_loop(
        session_id: u64,
        connection: Arc<C>,
        socket: Arc<UdpSocket>,
        token: CancellationToken,
        peer_addr: SocketAddr,
    ) {
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);
        let mut buf = vec![0u8; 65535];
        let fragment_id_counter = AtomicU16::new(0);

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    debug!("{} Downstream task for session {} cancelled.", peer_addr, session_id);
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from_addr)) => {
                            let data = Bytes::copy_from_slice(&buf[..len]);
                            let address = Address::from(from_addr);

                            let overhead = 1 + 8 + address.encoded_len(); // type + session_id + addr
                            if overhead + data.len() <= max_datagram_size {
                                let packet = UdpPacket::Unfragmented { session_id, address, data };
                                if let Ok(encoded) = packet.encode() {
                                    if connection.send_datagram(encoded).await.is_err() {
                                        break; // Connection is likely dead
                                    }
                                }
                            } else {
                                let fragment_id = fragment_id_counter.fetch_add(1, Ordering::Relaxed);
                                let fragments = UdpPacket::split_packet(
                                    session_id,
                                    address,
                                    data,
                                    max_datagram_size,
                                    fragment_id,
                                );
                                for fragment in fragments {
                                     if let Ok(encoded) = fragment.encode() {
                                        if connection.send_datagram(encoded).await.is_err() {
                                            break; // Connection is likely dead
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("{} Error receiving on UDP socket for session {}: {}", peer_addr, session_id, e);
                            break;
                        }
                    }
                }
            }
        }
    }

    fn shutdown(&self) {
        self.token.cancel();
    }
}
