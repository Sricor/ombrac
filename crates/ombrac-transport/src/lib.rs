use std::future::Future;
use std::io;

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
