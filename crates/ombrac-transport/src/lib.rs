use std::io;
use std::{future::Future, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "quic")]
pub mod quic;

pub trait Initiator: Send + Sync + 'static {
    fn open_bidirectional(&self) -> impl Future<Output = io::Result<impl Reliable>> + Send;
}

pub trait Acceptor: Send + Sync + 'static {
    fn accept_bidirectional(&self) -> impl Future<Output = io::Result<impl Reliable>> + Send;
}

pub trait Reliable: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

pub trait DatagramSender: Send + Sync + 'static {
    /// 异步发送一个数据报。
    ///
    /// # 参数
    /// * `dest` - 数据报的目标 `SocketAddr`。
    /// * `data` - 要发送的字节切片。
    fn send_datagram(
        &self,
        dest: SocketAddr,
        data: &[u8],
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// 一个用于接收不可靠数据报的 Trait，它会返回载荷和源地址。
///
/// 这模拟了 `UdpSocket::recv_from` 的行为。
pub trait DatagramReceiver: Send + Sync + 'static {
    /// 异步读取一个数据报。
    ///
    /// # 返回
    /// 一个 `io::Result`，其中包含一个元组 `(SocketAddr, Bytes)`，
    /// 分别代表数据来源的地址和接收到的数据。
    fn read_datagram(&self) -> impl Future<Output = io::Result<(SocketAddr, bytes::Bytes)>> + Send;
}

/// 一个组合 Trait，用于表示可以同时发送和接收数据报的类型。
pub trait Unreliable: DatagramSender + DatagramReceiver {}

/// 为所有同时实现了 `DatagramSender` 和 `DatagramReceiver` 的类型
/// 自动实现 `UnreliableDatagram`。
impl<T: DatagramSender + DatagramReceiver> Unreliable for T {}
