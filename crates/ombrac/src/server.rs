use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use ombrac_transport::{Acceptor, Reliable};

use crate::Secret;
use crate::client::Stream;
use crate::connect::Connect;

/// Represents a server that accepts connections from a transport layer.
///
/// It uses a generic `Acceptor` trait to remain transport-agnostic.
pub struct Server<T> {
    transport: T,
}

impl<T: Acceptor> Server<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    #[inline]
    pub async fn accept_connect(&self) -> io::Result<Stream<impl Reliable>> {
        let stream = self.transport.accept_bidirectional().await?;
        Ok(Stream(stream))
    }
}

impl Server<()> {
    pub async fn handle_connect<V, R>(
        validator: &V,
        mut stream: Stream<R>,
    ) -> io::Result<(u64, u64)>
    where
        V: Validator,
        R: Reliable + Send + Sync + 'static,
    {
        let connect = Connect::from_async_read(&mut stream).await?;

        let target = connect.address.to_socket_addr().await?;
        validator
            .is_valid(connect.secret, Some(target), None)
            .await?;

        let mut tcp_stream = TcpStream::connect(target).await?;

        crate::io::util::copy_bidirectional(&mut stream.0, &mut tcp_stream).await
    }
}

#[cfg(feature = "datagram")]
pub mod datagram {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use dashmap::DashMap;
    use ombrac_transport::{Acceptor, Unreliable};
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio::time::{MissedTickBehavior, interval};
    use tokio_util::sync::CancellationToken;

    use crate::associate::Associate;
    use crate::client::Datagram;

    use super::*;

    const MAX_CONCURRENT_ASSOCIATIONS: usize = 256;

    pub struct UdpHandlerConfig {
        pub idle_timeout: Duration,
        pub buffer_size: usize,
    }

    impl Default for UdpHandlerConfig {
        fn default() -> Self {
            Self {
                idle_timeout: Duration::from_secs(120),
                buffer_size: 1500,
            }
        }
    }

    struct NatEntry {
        socket: Arc<UdpSocket>,
        handle: JoinHandle<io::Result<()>>,
        last_active: Instant,
    }

    impl<T: Acceptor> Server<T> {
        pub async fn accept_associate(&self) -> io::Result<Datagram<impl Unreliable>> {
            let datagram = self.transport.accept_datagram().await?;
            Ok(Datagram(datagram))
        }
    }

    impl Server<()> {
        /// Handles a UDP associate session using a Cone NAT model suitable for protocols like QUIC.
        ///
        /// This implementation uses a single shared UDP socket for all outbound and inbound traffic
        /// for the entire duration of the client's association. This correctly handles protocols
        /// where the remote server may respond from a different IP address or port than the one
        /// the initial request was sent to.
        pub async fn handle_associate<V, U>(
            validator: &V,
            datagram: Datagram<U>,
            config: Arc<UdpHandlerConfig>,
        ) -> io::Result<()>
        where
            V: Validator + Clone + Copy,
            U: Unreliable + Send + Sync + 'static,
        {
            let datagram = Arc::new(datagram);
            let shutdown_token = CancellationToken::new();

            // Bind a single UDP socket to a random port for the entire session.
            let outbound_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

            // Shared timestamp to track the last activity for the entire session.
            let last_activity = Arc::new(Mutex::new(Instant::now()));

            let (secret_tx, secret_rx) = tokio::sync::watch::channel(None);

            // --- Task 1: Forward traffic from Client -> Target ---
            let client_to_target_handle = {
                let datagram = Arc::clone(&datagram);
                let outbound_socket = Arc::clone(&outbound_socket);
                let last_activity = Arc::clone(&last_activity);
                let validator = validator.clone(); // Assuming Validator can be cloned
                let token = shutdown_token.clone();

                tokio::spawn(async move {
                    let mut is_validated = false;
                    loop {
                        let validator = validator;
                        tokio::select! {
                            _ = token.cancelled() => break,
                            result = datagram.recv() => {
                                let packet = match result {
                                    Ok(p) => p,
                                    Err(e) => {
                                        // Client closed the connection or an error occurred.
                                        return Err(e);
                                    }
                                };

                                // Validate the secret only on the first packet of the session.
                            if secret_tx.is_closed() {
                                validator.is_valid(packet.secret, None, None).await?;
                                // Validation successful, send the secret to the other task.
                                // This also marks the secret as validated.
                                secret_tx.send(Some(packet.secret)).ok();
                            }

                                let target_addr = match packet.address.to_socket_addr().await {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        // Invalid address, just drop the packet.
                                        eprintln!("Failed to resolve address: {}", e);
                                        continue;
                                    }
                                };

                                if let Err(e) = outbound_socket.send_to(&packet.data, target_addr).await {
                                     // Error sending to target, might be a network issue.
                                    eprintln!("Failed to send UDP packet to {}: {}", target_addr, e);
                                    // We don't terminate the whole session for a single send error.
                                } else {
                                     // Update activity timestamp on successful send.
                                    *last_activity.lock().await = Instant::now();
                                }
                            }
                        }
                    }
                    Ok(())
                })
            };

            // --- Task 2: Forward traffic from Target -> Client ---
            let target_to_client_handle = {
                let datagram = Arc::clone(&datagram);
                let outbound_socket = Arc::clone(&outbound_socket);
                let last_activity = Arc::clone(&last_activity);
                let token = shutdown_token.clone();
                let buffer_size = config.buffer_size;
                let mut secret_rx = secret_rx.clone();

                tokio::spawn(async move {
                    // The secret is validated in the other task. We assume it remains constant.
                    let session_secret = match secret_rx.wait_for(|s| s.is_some()).await {
                        Ok(guard) => guard.unwrap(),
                        Err(_) => {
                            // The sender was dropped without sending a secret, meaning task 1 failed.
                            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "Secret validation failed"));
                        }
                    };

                    let mut buf = vec![0u8; buffer_size];

                    loop {
                        tokio::select! {
                             _ = token.cancelled() => break,
                             result = outbound_socket.recv_from(&mut buf) => {
                                 let (n, from_addr) = match result {
                                     Ok(res) => res,
                                     Err(e) => {
                                         // Socket error, terminate the task.
                                         return Err(e);
                                     }
                                 };

                                 // Update activity timestamp on successful receive.
                                 *last_activity.lock().await = Instant::now();

                                 let response_packet = Associate::with(
                                     session_secret,
                                     from_addr,
                                     Bytes::copy_from_slice(&buf[..n])
                                 );

                                 if datagram.send(response_packet).await.is_err() {
                                     // Client connection is likely closed, terminate the task.
                                     break;
                                 }
                             }
                        }
                    }
                    Ok(())
                })
            };

            // --- Task 3: Monitor session for idle timeout ---
            let timeout_handle = {
                let last_activity = Arc::clone(&last_activity);
                let idle_timeout = config.idle_timeout;
                let token = shutdown_token.clone();

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            _ = interval.tick() => {
                                if last_activity.lock().await.elapsed() > idle_timeout {
                                    // Session timed out, trigger shutdown.
                                    token.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };
            
            // Wait for any task to finish or for the session to be cancelled.
            tokio::select! {
                res = client_to_target_handle => res?,
                res = target_to_client_handle => res?,
                _ = shutdown_token.cancelled() => {
                    // Shutdown was triggered by timeout or externally.
                    Ok(())
                }
            }
        }
    }

    async fn proxy_target_to_client<U>(
        datagram: Arc<Datagram<U>>,
        udp_socket: Arc<UdpSocket>,
        session_secret: Secret,
        config: Arc<UdpHandlerConfig>,
    ) -> io::Result<()>
    where
        U: Unreliable,
    {
        let mut buf = vec![0u8; config.buffer_size];
        loop {
            let (n, from_addr) =
                match timeout(config.idle_timeout, udp_socket.recv_from(&mut buf)).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break,
                };

            let response_packet =
                Associate::with(session_secret, from_addr, Bytes::copy_from_slice(&buf[..n]));

            if let Err(_err) = datagram.send(response_packet).await {
                break;
            }
        }
        Ok(())
    }
}

pub trait Validator: Send + Sync + 'static {
    fn is_valid(
        &self,
        secret: Secret,
        target: Option<SocketAddr>,
        from: Option<SocketAddr>,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

#[derive(Clone, Copy)]
pub struct SecretValid(pub Secret);

impl Validator for SecretValid {
    async fn is_valid(
        &self,
        secret: Secret,
        _: Option<SocketAddr>,
        _: Option<SocketAddr>,
    ) -> io::Result<()> {
        if secret != self.0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid secret",
            ));
        }

        Ok(())
    }
}
