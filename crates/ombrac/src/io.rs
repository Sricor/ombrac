use std::future::Future;
use std::io;

use bytes::BytesMut;

pub use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait ToBytes {
    fn to_bytes(&self) -> BytesMut;
}

pub trait Streamable {
    fn write<T>(&self, stream: &mut T) -> impl Future<Output = io::Result<()>> + Send
    where
        Self: ToBytes + Send + Sync,
        T: AsyncWriteExt + Unpin + Send,
    {
        async move { stream.write_all(&self.to_bytes()).await }
    }

    fn read<T>(stream: &mut T) -> impl Future<Output = io::Result<Self>> + Send
    where
        Self: Sized,
        T: AsyncReadExt + Unpin + Send;
}

pub trait IntoSplit {
    fn into_split(
        self,
    ) -> (
        impl AsyncReadExt + Unpin + Send,
        impl AsyncWriteExt + Unpin + Send,
    );
}

mod impl_crates {
    mod impl_tokio {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        #[cfg(feature = "tokio-rustls")]
        use tokio_rustls::server::TlsStream;

        #[cfg(feature = "tokio-rustls")]
        use tokio_rustls::client::TlsStream as ClientTlsStream;

        use crate::io::IntoSplit;

        impl IntoSplit for TcpStream {
            fn into_split(
                self,
            ) -> (
                impl AsyncReadExt + Unpin + Send,
                impl AsyncWriteExt + Unpin + Send,
            ) {
                self.into_split()
            }
        }

        #[cfg(feature = "tokio-rustls")]
        impl IntoSplit for TlsStream<TcpStream> {
            fn into_split(
                self,
            ) -> (
                impl AsyncReadExt + Unpin + Send,
                impl AsyncWriteExt + Unpin + Send,
            ) {
                self.into_inner().0.into_split()
            }
        }

        #[cfg(feature = "tokio-rustls")]
        impl IntoSplit for ClientTlsStream<TcpStream> {
            fn into_split(
                self,
            ) -> (
                impl AsyncReadExt + Unpin + Send,
                impl AsyncWriteExt + Unpin + Send,
            ) {
                self.into_inner().0.into_split()
            }
        }
    }

    #[cfg(feature = "s2n-quic")]
    mod impl_s2n_quic {
        use s2n_quic::stream::BidirectionalStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::io::IntoSplit;

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
}
