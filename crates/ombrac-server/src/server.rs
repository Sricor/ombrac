use std::io;
use std::sync::Arc;

use futures::StreamExt;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::broadcast,
    task::JoinHandle,
};
use tokio_util::codec::Framed;

use ombrac::{
    protocol::{PROTOCOLS_VERSION, Secret, UdpPacket},
    upstream::{ProtocolCodec, UpstreamMessage},
};
use ombrac_macros::{debug, error, info};
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
        info!("Server is running, listening for connections...");
        loop {
            tokio::select! {
                accepted = self.acceptor.accept() => {
                    let connection = accepted?;
                    let secret = self.secret.clone();
                    info!("Accepted a new connection from client.");

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(connection, secret).await {
                            error!("Failed to handle connection: {}", e);
                        }
                    });
                },

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping accept loop.");
                    return Ok(());
                }
            }
        }
    }

    async fn handle_connection(connection: T::Connection, secret: Secret) -> io::Result<()> {
        let mut control_stream = connection.accept_bidirectional().await?;
        let mut framed_control = Framed::new(&mut control_stream, ProtocolCodec);

        // ClientHello
        // TODO: Timeout
        match framed_control.next().await {
            Some(Ok(UpstreamMessage::Hello(hello))) => {
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
                debug!("Client handshake successful.");
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Expected Hello message",
                ));
            }
        }

        let connection = Arc::new(connection);

        let tcp_handler = Self::spawn_tcp_handler(Arc::clone(&connection));
        let udp_handler = Self::spawn_udp_handler(Arc::clone(&connection));

        let _ = tokio::try_join!(tcp_handler, udp_handler);

        debug!("Client connection closed.");
        Ok(())
    }

    fn spawn_tcp_handler(connection: Arc<T::Connection>) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            loop {
                let stream = connection.accept_bidirectional().await?;
                info!("Accepted a new bidirectional stream for TCP.");

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_tcp_stream(stream).await {
                        error!("Error handling TCP stream: {}", e);
                    }
                });
            }
        })
    }

    async fn handle_tcp_stream(
        mut stream: <T::Connection as Connection>::Stream,
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

        let dest_addr_str = dest_addr.to_string();
        info!("Received TCP connect request to: {}", dest_addr_str);

        let mut dest_stream = TcpStream::connect(&dest_addr_str).await?;
        info!("Successfully connected to destination: {}", dest_addr_str);

        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;

        Ok(())
    }

    fn spawn_udp_handler(connection: Arc<T::Connection>) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let udp_socket = Arc::new(udp_socket);
            println!("UDP proxy socket bound to: {}", udp_socket.local_addr()?);

            let upstream_conn = Arc::clone(&connection);
            let upstream_sock = Arc::clone(&udp_socket);
            let upstream_handler = tokio::spawn(async move {
                loop {
                    let packet_bytes = upstream_conn.read_datagram().await?;
                    let packet = UdpPacket::decode(packet_bytes)?;
                    let dest_addr = packet.address.to_string();

                    upstream_sock.send_to(&packet.data, &dest_addr).await?;
                }
            });

            let downstream_conn = Arc::clone(&connection);
            let downstream_sock = Arc::clone(&udp_socket);
            let downstream_handler = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (len, from_addr) = downstream_sock.recv_from(&mut buf).await?;
                    let packet = UdpPacket {
                        address: from_addr.into(),
                        data: bytes::Bytes::copy_from_slice(&buf[..len]),
                    };

                    downstream_conn.send_datagram(packet.encode()).await?;
                }
            });

            tokio::select! {
                res = upstream_handler => res.unwrap_or(Ok(())),
                res = downstream_handler => res.unwrap_or(Ok(())),
            }
        })
    }
}
