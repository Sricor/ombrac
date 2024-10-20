use std::future::Future;
use std::io::Result;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod client;
pub mod request;
pub mod server;

pub trait Streamable {
    fn write<T>(&self, stream: &mut T) -> impl Future<Output = Result<()>> + Send
    where
        Self: ToBytes + Send + Sync,
        T: AsyncWriteExt + Unpin + Send,
    {
        async move { stream.write_all(&self.to_bytes()).await }
    }

    fn read<T>(stream: &mut T) -> impl Future<Output = Result<Self>> + Send
    where
        Self: Sized,
        T: AsyncReadExt + Unpin + Send;
}

pub trait ToBytes {
    fn to_bytes(&self) -> BytesMut;
}

pub trait Provider<T> {
    fn fetch(&mut self) -> impl Future<Output = Option<T>> + Send;
}

pub trait Resolver {
    fn lookup(&self, domain: &str, port: u16) -> impl Future<Output = Result<SocketAddr>> + Send;
}

pub trait IntoSplit {
    fn into_split(
        self,
    ) -> (
        impl AsyncReadExt + Unpin + Send,
        impl AsyncWriteExt + Unpin + Send,
    );
}

#[cfg(feature = "s2n-quic")]
mod s2n_quic {
    use s2n_quic::stream::BidirectionalStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::IntoSplit;

    impl IntoSplit for BidirectionalStream {
        fn into_split(
            self,
        ) -> (
            impl AsyncReadExt + Unpin + Send,
            impl AsyncWriteExt + Unpin + Send,
        ) {
            self.split()
        }
    }
}
