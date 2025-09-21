use std::io;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use bytes::{Bytes, BytesMut};
use tokio::{io::AsyncWriteExt, sync::Mutex};
use tokio_util::codec::Encoder;

use ombrac::{
    protocol::{Address, ClientConnect, ClientHello, PROTOCOLS_VERSION, Secret, UdpPacket},
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
}

impl<T, C> Client<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    pub async fn new(transport: T, secret: Secret, options: Option<Bytes>) -> io::Result<Self> {
        let options = options.unwrap_or(Bytes::new());
        let connection = Self::client_hello(&transport, secret, options.clone()).await?;

        Ok(Self {
            transport,
            connection: ArcSwap::new(connection.into()),
            reconnect_lock: Mutex::new(()),
            secret,
            options,
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
        let packet = UdpPacket {
            address: dest_addr,
            data,
        };
        let packet_bytes = packet.encode();

        self.with_retry(|conn| {
            let data_for_attempt = packet_bytes.clone();
            async move { conn.send_datagram(data_for_attempt).await }
        })
        .await
    }

    pub async fn read_datagram(&self) -> io::Result<(Address, Bytes)> {
        let packet_bytes = self
            .with_retry(|conn| async move { conn.read_datagram().await })
            .await?;

        match UdpPacket::decode(packet_bytes) {
            Ok(packet) => Ok((packet.address, packet.data)),
            Err(e) => {
                warn!("Failed to decode UDP packet: {}", e);
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    pub fn set_secret(&mut self, secret: Secret) {
        self.secret = secret
    }

    pub fn set_options(&mut self, options: Bytes) {
        self.options = options
    }

    pub async fn reconnect(&self) -> io::Result<()> {
        let _lock = self.reconnect_lock.lock().await;

        self.connection.store(Arc::new(
            Self::client_hello(&self.transport, self.secret, self.options.clone()).await?,
        ));

        Ok(())
    }

    async fn with_retry<F, Fut, R>(&self, operation: F) -> io::Result<R>
    where
        F: Fn(Guard<Arc<C>>) -> Fut,
        Fut: Future<Output = io::Result<R>>,
    {
        let connection = self.connection.load();
        match operation(connection).await {
            Ok(result) => Ok(result),
            Err(e)
                if e.kind() == io::ErrorKind::ConnectionReset
                    || e.kind() == io::ErrorKind::BrokenPipe
                    || e.kind() == io::ErrorKind::NotConnected =>
            {
                warn!("Connection lost, attempting to reconnect. Error: {}", e);
                self.reconnect().await?;
                info!("Reconnection successful, retrying operation.");
                let new_connection = self.connection.load();
                operation(new_connection).await
            }
            Err(e) => Err(e),
        }
    }
}
