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
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio::time::{MissedTickBehavior, interval};

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
        pub async fn handle_associate<V, U>(
            validator: &V,
            datagram: Datagram<U>,
            config: Arc<UdpHandlerConfig>,
        ) -> io::Result<()>
        where
            V: Validator,
            U: Unreliable + Send + Sync + 'static,
        {
            let datagram = Arc::new(datagram);
            let nat_table: Arc<DashMap<SocketAddr, NatEntry>> = Arc::new(DashMap::new());

            let nat_for_sweep = Arc::clone(&nat_table);
            let idle_timeout = config.idle_timeout;
            let sweeper_handle = tokio::spawn(async move {
                let mut tick = interval(Duration::from_secs(30));
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    nat_for_sweep.retain(|_addr, entry| {
                        if entry.last_active.elapsed() > idle_timeout {
                            entry.handle.abort();
                            false
                        } else {
                            true
                        }
                    });
                }
            });

            loop {
                let packet = match timeout(config.idle_timeout, datagram.recv()).await {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(e)) => {
                        return Err(e);
                    }
                    Err(_) => {
                        break;
                    }
                };

                if nat_table.is_empty() {
                    let session_secret = packet.secret;
                    validator.is_valid(session_secret, None, None).await?;
                }

                let target_addr = packet.address.to_socket_addr().await?;

                if !nat_table.contains_key(&target_addr) {
                    if nat_table.len() >= MAX_CONCURRENT_ASSOCIATIONS {
                        continue;
                    }

                    let bind_addr = match target_addr {
                        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
                    };

                    let outbound_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
                    let handle = tokio::spawn(proxy_target_to_client(
                        Arc::clone(&datagram),
                        Arc::clone(&outbound_socket),
                        packet.secret,
                        Arc::clone(&config),
                    ));

                    nat_table.insert(
                        target_addr,
                        NatEntry {
                            socket: Arc::clone(&outbound_socket),
                            handle,
                            last_active: Instant::now(),
                        },
                    );
                }

                if let Some(mut entry) = nat_table.get_mut(&target_addr) {
                    entry.last_active = Instant::now();
                    let outbound_socket = &entry.socket;

                    if let Err(_err) = outbound_socket.send_to(&packet.data, target_addr).await {
                        entry.handle.abort();
                        drop(entry);
                        nat_table.remove(&target_addr);
                    }
                }
            }

            sweeper_handle.abort();
            for entry in nat_table.iter() {
                entry.value().handle.abort();
            }
            nat_table.clear();

            Ok(())
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

pub trait Validator {
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
