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
    use std::time::Duration;

    use bytes::Bytes;
    use dashmap::DashMap;
    use ombrac_transport::{Acceptor, Unreliable};
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use crate::address::Address;
    use crate::associate::{Associate};
    use crate::client::Datagram;

    use super::*;

    // 配置保持不变
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

    impl<T: Acceptor> Server<T> {
        pub async fn accept_associate(&self) -> io::Result<Datagram<impl Unreliable>> {
            let datagram = self.transport.accept_datagram().await?;
            Ok(Datagram(datagram))
        }
    }

    impl Server<()> {
        /// ## Refactored UDP Handler
        ///
        /// This version is optimized for protocols like QUIC and WebRTC.
        ///
        /// Key improvements:
        /// 1.  **Single Socket per Client**: Creates only one outbound `UdpSocket` for the entire
        ///     client session, regardless of how many different destinations the client communicates with.
        ///     This massively reduces resource consumption.
        /// 2.  **Connection Migration Support**: The proxy is now agnostic to the client's source IP address.
        ///     As long as QUIC packets arrive through the `Datagram` channel, they will be forwarded correctly,
        ///     allowing QUIC's connection migration to function seamlessly.
        /// 3.  **Simplified State Management**: The complex NAT table mapping destinations to sockets is replaced
        ///     by a simple reverse-lookup map. A dedicated sweeper task is no longer needed; the session
        ///     times out monolithically if the client goes idle.
        pub async fn handle_associate_refactored<V, U>(
            validator: &V,
            datagram: Datagram<U>,
            config: Arc<UdpHandlerConfig>,
        ) -> io::Result<()>
        where
            V: Validator,
            U: Unreliable + Send + Sync + 'static,
        {
            // 1. 为整个客户端会话创建一个唯一的UDP Socket
            // 我们需要根据接收到的第一个数据包来决定是绑定到IPv4还是IPv6
            let first_packet = match timeout(config.idle_timeout, datagram.recv()).await {
                Ok(Ok(packet)) => packet,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()), // 客户端在超时前未发送任何数据，正常退出
            };

            // 验证第一个数据包
            validator
                .is_valid(first_packet.secret, None, None)
                .await?;

            let bind_addr: SocketAddr = match first_packet.address {
                Address::IPv4(_) => "0.0.0.0:0".parse().unwrap(),
                Address::IPv6(_) => "[::]:0".parse().unwrap(),
                
                // 如果是域名，我们默认尝试绑定到IPv4，也可以根据DNS解析结果来决定
                Address::Domain(_, _) => "0.0.0.0:0".parse().unwrap(),
            };

            let outbound_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
            let datagram = Arc::new(datagram);

            // 2. 创建一个反向NAT表
            // Key: 远程目标服务器的实际SocketAddr
            // Value: 客户端请求的原始Address (可能是域名)
            // 这用于在收到响应时，能将正确的原始地址封装后发回给客户端
            let reverse_nat: Arc<DashMap<SocketAddr, Address>> = Arc::new(DashMap::new());

            // 3. 启动一个任务，负责从outbound_socket接收所有响应并转发回客户端
            let inbound_handle = tokio::spawn(proxy_targets_to_client(
                Arc::clone(&datagram),
                Arc::clone(&outbound_socket),
                Arc::clone(&reverse_nat),
                first_packet.secret,
                Arc::clone(&config),
            ));

            // 处理第一个已经收到的数据包
            let target_addr = first_packet.address.clone().to_socket_addr().await?;
            reverse_nat.insert(target_addr, first_packet.address);
            outbound_socket
                .send_to(&first_packet.data, target_addr)
                .await?;

            // 4. 进入主循环，处理后续从客户端发来的数据
            loop {
                let packet = match timeout(config.idle_timeout, datagram.recv()).await {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(e)) => {
                        // 底层传输出现错误
                        inbound_handle.abort();
                        return Err(e);
                    }
                    Err(_) => {
                        // 客户端空闲超时
                        break;
                    }
                };

                // 使用同一个socket将数据发往目标地址
                let target_addr = packet.address.clone().to_socket_addr().await?;

                // 只有在新目标出现时才插入，减少DashMap写操作
                if !reverse_nat.contains_key(&target_addr) {
                    reverse_nat.insert(target_addr, packet.address);
                }

                if let Err(_e) = outbound_socket.send_to(&packet.data, target_addr).await {
                    // 发送失败可能是网络问题，可以选择记录日志或中断会话
                    // 这里我们选择继续，因为UDP本身就是不可靠的
                }
            }

            // 5. 客户端超时或连接关闭，清理资源
            inbound_handle.abort();
            Ok(())
        }
    }

    /// 这个任务监听唯一的出站socket，接收来自所有目标服务器的响应，
    /// 然后通过`datagram`通道将它们转发回原始客户端。
    async fn proxy_targets_to_client<U>(
        datagram: Arc<Datagram<U>>,
        udp_socket: Arc<UdpSocket>,
        reverse_nat: Arc<DashMap<SocketAddr, Address>>,
        session_secret: Secret,
        config: Arc<UdpHandlerConfig>,
    ) -> io::Result<()>
    where
        U: Unreliable,
    {
        let mut buf = vec![0u8; config.buffer_size];
        loop {
            // 注意：这里不再使用单独的超时，它的生命周期由父任务 `handle_associate_refactored` 控制
            let (n, from_addr) = udp_socket.recv_from(&mut buf).await?;

            // 从反向NAT表中查找客户端请求的原始地址
            // 如果找不到，说明这可能是一个我们未预期的包，或者是一个非常短暂连接的响应包
            // 在这种情况下，我们仍然用其实际IP地址转发回去，确保通信不会中断
            let original_address = reverse_nat
                .get(&from_addr)
                .map(|addr| addr.clone())
                .unwrap_or(Address::from(from_addr));

            let response_packet =
                Associate::with(session_secret, original_address, Bytes::copy_from_slice(&buf[..n]));

            if datagram.send(response_packet).await.is_err() {
                // 如果发送回客户端失败，说明客户端通道已关闭，此任务也应终止
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
