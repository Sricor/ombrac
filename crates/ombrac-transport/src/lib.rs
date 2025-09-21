use std::future::Future;
use std::io::Result;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "quic")]
pub mod quic;

pub trait Initiator: Send + Sync + 'static {
    type Connection: Connection;

    fn local_addr(&self) -> Result<SocketAddr>;
    fn connect(&self) -> impl Future<Output = Result<Self::Connection>> + Send;
}

pub trait Acceptor: Send + Sync + 'static {
    type Connection: Connection;

    fn local_addr(&self) -> Result<SocketAddr>;
    fn accept(&self) -> impl Future<Output = Result<Self::Connection>> + Send;
}

pub trait Connection: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync;
    fn open_bidirectional(&self) -> impl Future<Output = Result<Self::Stream>> + Send;
    fn accept_bidirectional(&self) -> impl Future<Output = Result<Self::Stream>> + Send;
    fn send_datagram(&self, data: bytes::Bytes) -> impl Future<Output = Result<()>> + Send;
    fn read_datagram(&self) -> impl Future<Output = Result<bytes::Bytes>> + Send;
}
