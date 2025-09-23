// client.rs

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use arc_swap::{ArcSwap, Guard};
use bytes::{Bytes, BytesMut};
use tokio::{io::AsyncWriteExt, sync::Mutex};
use tokio_util::codec::Encoder;

use ombrac::{
    protocol::{Address, ClientConnect, ClientHello, PROTOCOLS_VERSION, Secret, UdpPacket},
    reassembly::UdpReassembler, // 引入 UdpReassembler
    upstream::{ProtocolCodec, UpstreamMessage},
};
use ombrac_macros::{info, warn};
use ombrac_transport::{Connection, Initiator};

pub struct Client<T, C> {
    transport: T,
    connection: ArcSwap<C>,
    reconnect_lock: Mutex<()>,
    secret: Secret,
    options: Bytes,
    // 新增字段
    fragment_id_counter: AtomicU16,
    reassembler: UdpReassembler,
}

impl<T, C> Client<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    pub async fn new(transport: T, secret: Secret, options: Option<Bytes>) -> io::Result<Self> {
        let options = options.unwrap_or_default();
        let connection = Self::client_hello(&transport, secret, options.clone()).await?;

        Ok(Self {
            transport,
            connection: ArcSwap::new(connection.into()),
            reconnect_lock: Mutex::new(()),
            secret,
            options,
            fragment_id_counter: AtomicU16::new(0),
            reassembler: UdpReassembler::default(),
        })
    }

    async fn client_hello(transport: &T, secret: Secret, options: Bytes) -> io::Result<C> {
        let connection = transport.connect().await?;
        let mut stream = connection.open_bidirectional().await?;
        let mut codec = ProtocolCodec;
        let mut buf = BytesMut::new();
        let hello_message = UpstreamMessage::Hello(ClientHello {
            version: PROTOCOLS_VERSION,
            secret,
            options,
        });
        codec.encode(hello_message, &mut buf)?;
        stream.write_all(&buf).await?;
        Ok(connection)
    }

    pub async fn open_bidirectional(&self, dest_addr: Address) -> io::Result<C::Stream> {
        let mut stream = self
            .with_retry(|conn| async move { conn.open_bidirectional().await })
            .await?;
        let mut codec = ProtocolCodec;
        let mut buf = BytesMut::new();
        let connect_message = UpstreamMessage::Connect(ClientConnect { address: dest_addr });
        codec.encode(connect_message, &mut buf)?;
        stream.write_all(&buf).await?;
        Ok(stream)
    }

    pub async fn send_datagram(&self, dest_addr: Address, data: Bytes) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let connection = self.connection.load();
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1350);

        let overhead = 1 + dest_addr.encoded_len(); // 1 byte for type + address length
        let predicted_len = overhead + data.len();

        if predicted_len <= max_datagram_size {
            let unfragmented_packet = UdpPacket::Unfragmented {
                address: dest_addr,
                data,
            };
            let encoded = unfragmented_packet.encode()?;

            self.with_retry(|conn| {
                let data_for_attempt = encoded.clone();
                async move { conn.send_datagram(data_for_attempt).await }
            })
            .await?;
        } else {
            warn!(
                "UDP packet for {} is too large (predicted size {} > max {}), splitting...",
                dest_addr, predicted_len, max_datagram_size
            );

            let fragment_id = self.fragment_id_counter.fetch_add(1, Ordering::Relaxed);
            let fragments =
                UdpPacket::split_packet(dest_addr, data, max_datagram_size, fragment_id);

            let mut fragments = fragments.peekable();
            if fragments.peek().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Packet is too large to be fragmented and sent (exceeds MTU or fragment count limit)",
                ));
            }

            for fragment in fragments {
                let packet_bytes = fragment.encode()?;
                self.with_retry(|conn| {
                    let data_for_attempt = packet_bytes.clone();
                    async move { conn.send_datagram(data_for_attempt).await }
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn read_datagram(&self) -> io::Result<(Address, Bytes)> {
        loop {
            let packet_bytes = self
                .with_retry(|conn| async move { conn.read_datagram().await })
                .await?;

            let packet = match UdpPacket::decode(packet_bytes) {
                Ok(packet) => packet,
                Err(_e) => {
                    warn!("Failed to decode UDP packet: {}", _e);
                    continue;
                }
            };

            match self.reassembler.process(packet) {
                Ok(Some((address, data))) => {
                    return Ok((address, data));
                }
                Ok(None) => {
                    continue;
                }
                Err(_e) => {
                    warn!("UDP reassembly error: {}", _e);
                    continue;
                }
            }
        }
    }

    pub fn set_secret(&mut self, secret: Secret) {
        self.secret = secret
    }

    pub fn set_options(&mut self, options: Bytes) {
        self.options = options
    }

    pub async fn reconnect(&self, old_conn_id: usize) -> io::Result<()> {
        let _lock = self.reconnect_lock.lock().await;

        let current_conn_id = Arc::as_ptr(&self.connection.load()) as usize;
        if current_conn_id == old_conn_id {
            info!("Connection is still stale, performing reconnection.");
            let new_connection =
                Self::client_hello(&self.transport, self.secret, self.options.clone()).await?;
            self.connection.store(Arc::new(new_connection));
        } else {
            info!("Connection already re-established by another task. Skipping reconnection.");
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
                info!("Reconnection successful, retrying operation.");
                let new_connection = self.connection.load();
                operation(new_connection).await
            }
            Err(e) => Err(e),
        }
    }
}
