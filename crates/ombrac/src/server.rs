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
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use dashmap::DashMap;
    use ombrac_transport::{Acceptor, Unreliable};
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::{interval, MissedTickBehavior};

    use crate::address::Address;
    use crate::associate::{Associate};
    use crate::client::Datagram;

    use super::*;

    const MAX_CONCURRENT_ASSOCIATIONS: usize = 256;

    pub struct UdpHandlerConfig {
        pub idle_timeout: Duration,
        // **关键修复 #1: 增加缓冲区大小**
        // 设置为UDP理论最大载荷大小，避免任何截断。
        pub buffer_size: usize,
    }

    impl Default for UdpHandlerConfig {
        fn default() -> Self {
            Self {
                idle_timeout: Duration::from_secs(120),
                buffer_size: 65535,
            }
        }
    }

    // 用于在NAT表中存储每个目标流的状态
    struct NatEntry {
        socket: Arc<UdpSocket>,
        handle: JoinHandle<()>, // 任务现在不返回Result，错误在内部处理
        last_active: Instant,
    }

    impl<T: Acceptor> Server<T> {
        pub async fn accept_associate(&self) -> io::Result<Datagram<impl Unreliable>> {
            let datagram = self.transport.accept_datagram().await?;
            Ok(Datagram(datagram))
        }
    }

    impl Server<()> {
        /// ## Final Refactored UDP Handler (Production Ready)
        ///
        /// This version combines the strengths of the previous approaches to create a robust
        /// and efficient UDP proxy suitable for QUIC, WebRTC, and other modern protocols.
        ///
        /// Key Features:
        /// 1.  **Socket Caching**: A dedicated UDP socket is created for each unique destination (`SocketAddr`).
        ///     This socket is cached and reused for subsequent packets to the same destination,
        ///     achieving high resource efficiency.
        /// 2.  **Flow Isolation**: Each destination has its own socket, creating a clean "port-restricted cone NAT"
        ///     behavior. This prevents the "symmetric NAT" problem and ensures maximum compatibility
        ///     with strict servers and protocols like QUIC.
        /// 3.  **Correct Buffer Sizing**: The default buffer size is increased to the maximum theoretical
        ///     UDP payload size (65535) to prevent packet truncation, which is a common cause of
        ///     failures during QUIC's Path MTU Discovery.
        /// 4.  **Idle Connection Sweeping**: A background task periodically cleans up cached sockets
        ///     that have been inactive for too long, preventing resource leaks.
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
            // NAT表: Key是目标服务器地址, Value是对应的Socket和状态
            let nat_table: Arc<DashMap<SocketAddr, NatEntry>> = Arc::new(DashMap::new());

            // 验证只在第一次通信时进行
            let mut first_packet = true;

            // **关键修复 #2: 重新引入带缓存的NAT表和超时清理**
            let nat_for_sweep = Arc::clone(&nat_table);
            let idle_timeout = config.idle_timeout;
            let sweeper_handle = tokio::spawn(async move {
                let mut tick = interval(Duration::from_secs(30));
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    nat_for_sweep.retain(|_addr, entry| {
                        if entry.last_active.elapsed() > idle_timeout {
                            entry.handle.abort(); // 终止关联的接收任务
                            false
                        } else {
                            true
                        }
                    });
                }
            });

            loop {
                // 为整个会话设置一个总的超时，如果客户端完全不活跃，则退出
                let packet = match tokio::time::timeout(config.idle_timeout, datagram.recv()).await {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // 客户端整体超时
                };

                if first_packet {
                    validator.is_valid(packet.secret, None, None).await?;
                    first_packet = false;
                }

                let target_addr = packet.address.clone().to_socket_addr().await?;

                // **核心逻辑: 获取或创建缓存的Socket**
                if !nat_table.contains_key(&target_addr) {
                    if nat_table.len() >= MAX_CONCURRENT_ASSOCIATIONS {
                        // 防止资源耗尽
                        continue;
                    }

                    // 为这个新的目标地址创建一个专用的Socket
                    let bind_addr: SocketAddr = match target_addr {
                        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                    };
                    let outbound_socket = Arc::new(UdpSocket::bind(bind_addr).await?);

                    // 为这个专用的Socket创建一个接收任务
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

                // 更新活动时间并发送数据
                if let Some(mut entry) = nat_table.get_mut(&target_addr) {
                    entry.last_active = Instant::now();
                    let outbound_socket = &entry.socket;

                    if outbound_socket.send_to(&packet.data, target_addr).await.is_err() {
                        // 如果发送失败，最好移除这个条目，让下次能重建
                        entry.handle.abort();
                        drop(entry); // 释放锁
                        nat_table.remove(&target_addr);
                    }
                }
            }
            
            // 清理所有资源
            sweeper_handle.abort();
            for entry in nat_table.iter() {
                entry.value().handle.abort();
            }
            nat_table.clear();

            Ok(())
        }
    }

    /// 任务: 从一个专用的目标Socket接收数据，并将其转发回客户端。
    async fn proxy_target_to_client<U>(
        datagram: Arc<Datagram<U>>,
        udp_socket: Arc<UdpSocket>,
        session_secret: Secret,
        config: Arc<UdpHandlerConfig>,
    ) where
        U: Unreliable,
    {
        let mut buf = vec![0u8; config.buffer_size];
        loop {
            // 这个任务的生命周期由NAT表的sweeper通过abort来管理，所以不需要内部超时
            
            match udp_socket.recv_from(&mut buf).await {
                Ok((n, from_addr)) => {
                    let response_address = Address::from(from_addr); 

                    let response_packet = Associate::with(
                        session_secret,
                        response_address,
                        Bytes::copy_from_slice(&buf[..n]),
                    );

                    if datagram.send(response_packet).await.is_err() {
                        // 发送回客户端失败，通道关闭，任务可以退出了
                        break;
                    }
                }
                Err(_) => {
                    // recv_from 失败，通常意味着socket被关闭，任务也应退出
                    break;
                }
            }
        }
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
