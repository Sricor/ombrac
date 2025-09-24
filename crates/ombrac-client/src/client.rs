// client.rs

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use arc_swap::{ArcSwap, Guard};
use bytes::Bytes;
use dashmap::DashMap;
use ombrac::reassembly::UdpReassembler;
use tokio::{
    io::AsyncWriteExt, // Added AsyncReadExt for read_u32
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use ombrac::{
    protocol::{self, Address, ClientConnect, ClientHello, PROTOCOLS_VERSION, Secret, UdpPacket},
    upstream::UpstreamMessage,
};
use ombrac_macros::{debug, info, warn};
use ombrac_transport::{Connection, Initiator};

// This type alias was missing but seems implied by other code.
// If your transport library provides this, you can remove this.
mod config {}

type UdpDispatcher = mpsc::Sender<(Bytes, Address)>;

/// The central client responsible for managing the connection to the server.
///
/// This client handles TCP streams and acts as a factory for UDP sessions.
/// It runs a background task to dispatch all incoming UDP datagrams to their
/// respective sessions.
pub struct Client<T, C> {
    // Inner state is Arc'd to be shared with the background dispatcher task.
    inner: Arc<ClientInner<T, C>>,
    // The handle to the background task, used for graceful shutdown.
    _dispatcher_handle: JoinHandle<()>,
}

struct ClientInner<T, C> {
    transport: T,
    connection: ArcSwap<C>,
    reconnect_lock: Mutex<()>,
    secret: Secret,
    options: Bytes,
    fragment_id_counter: AtomicU16,
    session_id_counter: AtomicU64,
    reassembler: UdpReassembler,
    // The core of the UDP dispatch mechanism. Maps session_id to a sender
    // that forwards data to the corresponding `UdpSession`.
    udp_dispatch_map: DashMap<u64, UdpDispatcher>,
    // Token to signal the background dispatcher to shut down.
    shutdown_token: CancellationToken,
}

/// A virtual UDP session over the tunnel.
///
/// It provides a high-level, socket-like API (`send_to`, `recv_from`)
/// for a single UDP conversation.
///
/// When this struct is dropped, its session is automatically cleaned up
/// on the client side.
pub struct UdpSession<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    session_id: u64,
    client_inner: Arc<ClientInner<T, C>>,
    receiver: mpsc::Receiver<(Bytes, Address)>,
}

impl<T, C> Drop for UdpSession<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    fn drop(&mut self) {
        // When a session is dropped, remove its dispatcher from the map
        // to prevent the map from growing indefinitely.
        self.client_inner.udp_dispatch_map.remove(&self.session_id);
        debug!("UDP session {} dropped and cleaned up.", self.session_id);
    }
}

impl<T, C> UdpSession<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    /// Sends a UDP datagram to the specified destination address through the tunnel.
    pub async fn send_to(&self, data: Bytes, dest_addr: Address) -> io::Result<()> {
        self.client_inner
            .internal_send_datagram(self.session_id, dest_addr, data)
            .await
    }

    /// Receives a UDP datagram from the tunnel for this session.
    ///
    /// Returns the received data and the original sender's address.
    pub async fn recv_from(&mut self) -> Option<(Bytes, Address)> {
        self.receiver.recv().await
    }
}

impl<T, C> Client<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection,
{
    pub async fn new(transport: T, secret: Secret, options: Option<Bytes>) -> io::Result<Self> {
        let options = options.unwrap_or_default();
        let connection = Self::client_hello(&transport, secret, options.clone()).await?;

        let inner = Arc::new(ClientInner {
            transport,
            connection: ArcSwap::new(Arc::new(connection)),
            reconnect_lock: Mutex::new(()),
            secret,
            options,
            fragment_id_counter: AtomicU16::new(0),
            session_id_counter: AtomicU64::new(1),
            reassembler: UdpReassembler::default(),
            udp_dispatch_map: DashMap::new(),
            shutdown_token: CancellationToken::new(),
        });

        // Spawn the background task that reads all UDP datagrams and dispatches them.
        let dispatcher_handle = tokio::spawn(Self::run_udp_dispatcher(Arc::clone(&inner)));

        Ok(Self {
            inner,
            _dispatcher_handle: dispatcher_handle,
        })
    }

    /// Establishes a new UDP session through the tunnel.
    ///
    /// This returns a `UdpSession` object that can be used to send and receive
    /// UDP datagrams as if it were a regular UDP socket.
    pub fn connect_udp(&self) -> UdpSession<T, C> {
        let session_id = self.inner.new_session_id();
        let (tx, rx) = mpsc::channel(128); // Channel buffer size

        self.inner.udp_dispatch_map.insert(session_id, tx);

        UdpSession {
            session_id,
            client_inner: Arc::clone(&self.inner),
            receiver: rx,
        }
    }

    /// Opens a new bidirectional stream for TCP-like communication.
    pub async fn open_bidirectional(&self, dest_addr: Address) -> io::Result<C::Stream> {
        let mut stream = self
            .inner
            .with_retry(|conn| async move { conn.open_bidirectional().await })
            .await?;

        // CHANGED: Use our protocol helper to encode the message
        let connect_message = UpstreamMessage::Connect(ClientConnect { address: dest_addr });
        let encoded_bytes = protocol::encode(&connect_message)?;

        // Write length prefix + payload
        stream.write_u32(encoded_bytes.len() as u32).await?;
        stream.write_all(&encoded_bytes).await?;

        Ok(stream)
    }

    /// The background task that continuously reads datagrams from the server
    /// and dispatches them to the correct `UdpSession`.
    async fn run_udp_dispatcher(inner: Arc<ClientInner<T, C>>) {
        info!("UDP dispatcher task started.");
        loop {
            tokio::select! {
                // Listen for the shutdown signal
                _ = inner.shutdown_token.cancelled() => {
                    info!("UDP dispatcher task shutting down.");
                    break;
                }
                // Read the next datagram from the server
                result = inner.internal_read_datagram() => {
                    match result {
                        Ok((session_id, address, data)) => {
                            // Find the corresponding session sender in the map
                            if let Some(tx) = inner.udp_dispatch_map.get(&session_id) {
                                debug!(
                                    "UDP Dispatcher: Forwarding {} bytes from {} to session [{}].",
                                    data.len(), address, session_id
                                );

                                // Send the data to the session. If it fails, the receiver
                                // (UdpSession) has been dropped, so we can clean up.
                                if tx.send((data, address)).await.is_err() {
                                    inner.udp_dispatch_map.remove(&session_id);
                                }
                            } else {
                                warn!(
                                    "UDP Dispatcher: Received UDP datagram for UNKNOWN or CLOSED session: {}",
                                    session_id
                                );
                            }
                        }
                        Err(e) => {
                             // If the error is critical (e.g., connection truly closed),
                             // the `internal_read_datagram`'s retry logic will handle it.
                             // If reconnection fails, it will return an error and we can stop.
                            warn!("Error reading datagram in dispatcher: {}. Retrying...", e);
                             // A small delay to prevent tight loop on persistent errors
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    async fn client_hello(transport: &T, secret: Secret, options: Bytes) -> io::Result<C> {
        let connection = transport.connect().await?;
        let mut stream = connection.open_bidirectional().await?;

        // CHANGED: Use our protocol helper to encode the message
        let hello_message = UpstreamMessage::Hello(ClientHello {
            version: PROTOCOLS_VERSION,
            secret,
            options,
        });

        let encoded_bytes = protocol::encode(&hello_message)?;

        // Write length prefix + payload
        stream.write_u32(encoded_bytes.len() as u32).await?;
        stream.write_all(&encoded_bytes).await?;

        Ok(connection)
    }
}

impl<T, C> Drop for Client<T, C> {
    fn drop(&mut self) {
        // Signal the background task to shut down when the client is dropped.
        self.inner.shutdown_token.cancel();
    }
}

// These methods are now part of the internal implementation
impl<T, C> ClientInner<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    fn new_session_id(&self) -> u64 {
        self.session_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Internal method to send a datagram, handling fragmentation.
    async fn internal_send_datagram(
        &self,
        session_id: u64,
        dest_addr: Address,
        data: Bytes,
    ) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let connection = self.connection.load();
        // Use a conservative default if max_datagram_size is not available.
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);

        // A reasonable guess for payload size, leaving room for headers.
        let max_payload_size = max_datagram_size.saturating_sub(128);

        if data.len() <= max_payload_size {
            let unfragmented_packet = UdpPacket::Unfragmented {
                session_id,
                address: dest_addr,
                data,
            };
            // FIXED: Use the implemented UdpPacket::encode method
            let encoded = unfragmented_packet.encode()?;
            debug!(
                "Client Internals [{}]: Sending UNFRAGMENTED packet ({} bytes) over transport.",
                session_id,
                encoded.len()
            );

            self.with_retry(|conn| {
                let data_for_attempt = encoded.clone();
                async move { conn.send_datagram(data_for_attempt).await }
            })
            .await?;
        } else {
            warn!(
                "Client Internals [{}]: Packet for {} is too large (size {} > max {}), splitting...",
                session_id,
                dest_addr,
                data.len(),
                max_payload_size
            );

            let fragment_id = self.fragment_id_counter.fetch_add(1, Ordering::Relaxed);
            // FIXED: Use the implemented UdpPacket::split_packet method
            let fragments = UdpPacket::split_packet(
                session_id,
                dest_addr.clone(),
                data,
                max_payload_size,
                fragment_id,
            );

            for (i, fragment) in fragments.enumerate() {
                // FIXED: Use the implemented UdpPacket::encode method
                let packet_bytes = fragment.encode()?;
                debug!(
                    "Client Internals [{}]: Sending FRAGMENT #{} (frag_id: {}) ({} bytes) for {}",
                    session_id,
                    i,
                    fragment_id,
                    packet_bytes.len(),
                    dest_addr
                );
                self.with_retry(|conn| {
                    let data_for_attempt = packet_bytes.clone();
                    async move { conn.send_datagram(data_for_attempt).await }
                })
                .await?;
            }
        }
        Ok(())
    }

    /// Internal method to read a complete datagram, handling reassembly.
    async fn internal_read_datagram(&self) -> io::Result<(u64, Address, Bytes)> {
        loop {
            let packet_bytes = self
                .with_retry(|conn| async move { conn.read_datagram().await })
                .await?;

            debug!(
                "Client Internals: Received {} bytes from transport.",
                packet_bytes.len()
            );

            // FIXED: Use the implemented UdpPacket::decode method
            let packet = match UdpPacket::decode(packet_bytes) {
                Ok(packet) => packet,
                Err(e) => {
                    warn!("Failed to decode UDP packet: {}", e);
                    continue;
                }
            };

            match self.reassembler.process(packet).await {
                Ok(Some((session_id, address, data))) => {
                    info!(
                        "Client Internals [{}]: Successfully reassembled packet from {}. Total size: {} bytes.",
                        session_id,
                        address,
                        data.len()
                    );
                    return Ok((session_id, address, data));
                }
                Ok(None) => {
                    debug!("Client Internals: Received a fragment, waiting for more parts.");
                    continue;
                } // Fragment received, continue reading.
                Err(e) => {
                    warn!("UDP reassembly error: {}", e);
                    continue;
                }
            }
        }
    }

    async fn reconnect(&self, old_conn_id: usize) -> io::Result<()> {
        let _lock = self.reconnect_lock.lock().await;
        let current_conn_id = Arc::as_ptr(&self.connection.load()) as usize;

        if current_conn_id == old_conn_id {
            info!("Connection is stale, performing reconnection.");
            let new_connection =
                Client::<T, C>::client_hello(&self.transport, self.secret, self.options.clone())
                    .await?;
            self.connection.store(Arc::new(new_connection));
            info!("Reconnection successful.");
        } else {
            info!("Connection already re-established by another task.");
        }
        Ok(())
    }

    async fn with_retry<F, Fut, R>(&self, operation: F) -> io::Result<R>
    where
        F: Fn(Guard<Arc<C>>) -> Fut,
        Fut: Future<Output = io::Result<R>>,
    {
        let connection = self.connection.load();
        let old_conn_id = Arc::as_ptr(&connection) as usize;
        match operation(connection).await {
            Ok(result) => Ok(result),
            Err(e)
                if e.kind() == io::ErrorKind::ConnectionReset
                    || e.kind() == io::ErrorKind::BrokenPipe
                    || e.kind() == io::ErrorKind::NotConnected
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                warn!("Connection lost, attempting to reconnect. Error: {}", e);
                self.reconnect(old_conn_id).await?;
                let new_connection = self.connection.load();
                operation(new_connection).await
            }
            Err(e) => Err(e),
        }
    }
}
