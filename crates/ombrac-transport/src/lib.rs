use std::error::Error;
use std::future::Future;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "quic")]
pub mod quic;

pub trait Transport: Send {
    fn unreliable(&self) -> impl Future<Output = Result<impl Unreliable>> + Send;
    fn reliable(&self) -> impl Future<Output = Result<impl Reliable>> + Send;
}

pub trait Unreliable: Send + Sync + 'static {
    fn send(&self, data: Bytes) -> impl Future<Output = Result<()>> + Send;
    fn recv(&self) -> impl Future<Output = Result<Bytes>> + Send;
}

pub trait Reliable: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
