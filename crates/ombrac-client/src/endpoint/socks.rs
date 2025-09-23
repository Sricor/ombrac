use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use socks_lib::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use socks_lib::v5::server::Handler;
use socks_lib::v5::{
    Address as Socks5Address, Request, Response, Stream, UdpPacket as SocksUdpPacket,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ombrac::protocol::Address as OmbracAddress;
use ombrac_macros::{debug, error, info, warn};
use ombrac_transport::{Connection, Initiator};

use crate::client::Client;

type UdpMessage = (OmbracAddress, bytes::Bytes);

/// Manages UDP sessions by dispatching incoming datagrams from the client
/// to the appropriate handler based on the session ID.
struct UdpDispatcher<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    client: Arc<Client<T, C>>,
    sessions: DashMap<u64, mpsc::Sender<UdpMessage>>,
    token: CancellationToken,
}

impl<T, C> UdpDispatcher<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    fn new(client: Arc<Client<T, C>>) -> Arc<Self> {
        let dispatcher = Arc::new(Self {
            client,
            sessions: DashMap::new(),
            token: CancellationToken::new(),
        });
        Self::spawn_reader_task(Arc::clone(&dispatcher));
        dispatcher
    }

    /// Spawns the main task that reads all datagrams from the remote
    /// and dispatches them to session-specific channels.
    fn spawn_reader_task(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = self.token.cancelled() => {
                        info!("UDP dispatcher reader task shutting down.");
                        break;
                    }
                    result = self.client.read_datagram() => {
                        match result {
                            Ok((session_id, addr, data)) => {
                                if let Some(tx) = self.sessions.get(&session_id) {
                                    if tx.send((addr, data)).await.is_err() {
                                        // Receiver was dropped, session likely ended.
                                        self.sessions.remove(&session_id);
                                    }
                                } else {
                                    warn!("Received UDP packet for unknown session ID: {}", session_id);
                                }
                            }
                            Err(_e) => {
                                error!("Error reading datagram from client, UDP dispatcher closing: {}", _e);
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Registers a new UDP session, returning a unique session ID and a channel receiver.
    fn register(&self) -> (u64, mpsc::Receiver<UdpMessage>) {
        let session_id = self.client.new_session_id();
        let (tx, rx) = mpsc::channel(128);
        self.sessions.insert(session_id, tx);
        (session_id, rx)
    }

    /// Unregisters a UDP session, cleaning up its resources.
    fn deregister(&self, session_id: u64) {
        self.sessions.remove(&session_id);
    }
}

impl<T, C> Drop for UdpDispatcher<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.token.cancel();
    }
}

pub struct CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    client: Arc<Client<T, C>>,
    udp_dispatcher: Arc<UdpDispatcher<T, C>>,
}

impl<T, C> CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    pub fn new(client: Arc<Client<T, C>>) -> Self {
        let udp_dispatcher = UdpDispatcher::new(Arc::clone(&client));
        Self {
            client,
            udp_dispatcher,
        }
    }

    async fn handle_connect(
        &self,
        address: Socks5Address,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<(u64, u64)> {
        let addr = util::socks_to_ombrac_addr(address)?;
        let mut outbound = self.client.open_bidirectional(addr).await?;
        ombrac_transport::io::copy_bidirectional(stream, &mut outbound).await
    }

    async fn handle_associate(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        let inbound_udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let inbound_addr = inbound_udp.local_addr()?;

        // The address that the SOCKS client should use for its replies.
        let reply_addr = SocketAddr::new(stream.local_addr().ip(), inbound_addr.port());
        let bind_addr = Socks5Address::from(reply_addr);
        stream
            .write_response(&Response::Success(&bind_addr))
            .await?;

        info!(
            "SOCKS UDP association created for {}. Client should send UDP to {}",
            stream.peer_addr().ip(),
            bind_addr
        );

        // Register a new session with the dispatcher
        let (session_id, mut incoming_from_remote_rx) = self.udp_dispatcher.register();
        debug!("New UDP session registered with ID: {}", session_id);

        let idle_timeout = Duration::from_secs(120);

        let mut buf = vec![0u8; 65535];
        let (_len, client_udp_addr) =
            match tokio::time::timeout(idle_timeout, inbound_udp.recv_from(&mut buf)).await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    info!(
                        "SOCKS UDP association for {} timed out waiting for first packet.",
                        stream.peer_addr().ip()
                    );
                    return Ok(());
                }
            };

        info!(
            "Received first UDP packet from client at {}",
            client_udp_addr
        );

        let inbound_udp_clone = Arc::clone(&inbound_udp);
        let remote_to_client_task = tokio::spawn(async move {
            while let Some((origin_addr, data)) = incoming_from_remote_rx.recv().await {
                let Ok(socks_addr) = util::ombrac_addr_to_socks(origin_addr) else {
                    continue;
                };
                let response_packet = SocksUdpPacket::un_frag(socks_addr, data);
                if let Err(_e) = inbound_udp_clone
                    .send_to(&response_packet.to_bytes(), client_udp_addr)
                    .await
                {
                    error!(
                        "Failed to send UDP packet to SOCKS client {}: {}",
                        client_udp_addr, _e
                    );
                    break;
                }
            }
        });

        let client = Arc::clone(&self.client);
        let client_to_remote_task = tokio::spawn(async move {
            // Process the first packet that we already received
            if let Err(_e) = Self::process_client_packet(&client, session_id, &buf[.._len]).await {
                error!("Error processing first UDP packet: {}", _e);
                return;
            }

            // Process subsequent packets
            loop {
                match inbound_udp.recv_from(&mut buf).await {
                    Ok((len, src_addr)) => {
                        if src_addr != client_udp_addr {
                            warn!(
                                "Received UDP packet from unexpected source {}, expected {}. Ignoring.",
                                src_addr, client_udp_addr
                            );
                            continue;
                        }
                        if let Err(_e) =
                            Self::process_client_packet(&client, session_id, &buf[..len]).await
                        {
                            error!("Error processing UDP packet from client: {}", _e);
                            break;
                        }
                    }
                    Err(_e) => {
                        error!("Error receiving from SOCKS UDP socket: {}", _e);
                        break;
                    }
                }
            }
        });

        let mut tcp_check_buf = [0u8; 1];
        let peer_addr = stream.peer_addr().ip();
        tokio::select! {
            _ = stream.read(&mut tcp_check_buf) => {
                info!("SOCKS TCP control connection for {} closed, ending UDP association.", peer_addr);
            },
            _ = remote_to_client_task => {
                info!("Ombrac->Client UDP task finished for {}.", peer_addr);
            },
            _ = client_to_remote_task => {
                info!("Client->Ombrac UDP task finished for {}.", peer_addr);
            },
        }

        self.udp_dispatcher.deregister(session_id);
        info!("[UDP] Association for {} ended.", peer_addr);
        Ok(())
    }

    async fn process_client_packet(
        client: &Client<T, C>,
        session_id: u64,
        raw: &[u8],
    ) -> io::Result<()> {
        let pkt = SocksUdpPacket::from_bytes(&mut &raw[..]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse SOCKS UDP packet: {e}"),
            )
        })?;

        if pkt.frag != 0 {
            warn!("Dropping fragmented SOCKS5 UDP packet, which is not supported.");
            return Ok(());
        }

        let dest_addr = util::socks_to_ombrac_addr(pkt.address)?;
        client.send_datagram(session_id, dest_addr, pkt.data).await
    }
}

impl<T, C> Handler for CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    async fn handle<S>(&self, stream: &mut Stream<S>, request: Request) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!("SOCKS Request: {:?}", request);

        match request {
            Request::Connect(address) => {
                stream.write_response_unspecified().await?;

                match self.handle_connect(address.clone(), stream).await {
                    Ok((up, down)) => {
                        info!(
                            "{} Connect {}, Send: {}, Recv: {}",
                            stream.peer_addr().ip(),
                            address,
                            up,
                            down
                        );
                    }
                    Err(err) => {
                        error!("SOCKS connect to {} failed: {}", address, err);
                        return Err(err);
                    }
                }
            }
            Request::Associate(_) => self.handle_associate(stream).await?,
            _ => {
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

mod util {
    use ombrac::protocol::Address as OmbracAddress;
    use socks_lib::v5::Address as Socks5Address;
    use std::io;

    pub(super) fn socks_to_ombrac_addr(addr: Socks5Address) -> io::Result<OmbracAddress> {
        let result = match addr {
            Socks5Address::IPv4(value) => OmbracAddress::SocketV4(value),
            Socks5Address::IPv6(value) => OmbracAddress::SocketV6(value),
            Socks5Address::Domain(domain, port) => {
                OmbracAddress::Domain(domain.as_bytes().to_owned(), port)
            }
        };

        Ok(result)
    }

    pub(super) fn ombrac_addr_to_socks(addr: OmbracAddress) -> io::Result<Socks5Address> {
        let result = match addr {
            OmbracAddress::SocketV4(sa) => Socks5Address::IPv4(sa),
            OmbracAddress::SocketV6(sa) => Socks5Address::IPv6(sa),
            OmbracAddress::Domain(domain_bytes, port) => {
                Socks5Address::Domain(domain_bytes.try_into()?, port)
            }
        };

        Ok(result)
    }
}
