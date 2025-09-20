use std::net::SocketAddr;

use tokio::io;
use tokio::io::AsyncWriteExt;

use ombrac_transport::{Initiator, Reliable, Unreliable};

use crate::Secret;
use crate::address::Address;
use crate::connect::Connect;

pub struct Client<T> {
    transport: T,
}

impl<T: Initiator + Unreliable> Client<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub async fn connect<A: Into<Address>>(
        &self,
        target: A,
        secret: Secret,
    ) -> io::Result<Stream<impl Reliable>> {
        let mut stream = self.transport.open_bidirectional().await?;

        let request = Connect::with(secret, target);
        stream.write_all(&request.to_bytes()?).await?;

        Ok(Stream(stream))
    }

    pub async fn send_datagram(&self, dest: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.transport.send_datagram(dest, data).await
    }

    pub async fn read_datagram(&self) -> io::Result<(SocketAddr, bytes::Bytes)> {
        self.transport.read_datagram().await
    }
}

pub struct Stream<R: Reliable>(pub(crate) R);

mod impl_async_read {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::{Reliable, Stream};

    impl<R: Reliable> AsyncRead for Stream<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.get_mut().0), cx, buf)
        }
    }

    impl<R: Reliable> AsyncWrite for Stream<R> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            AsyncWrite::poll_write(Pin::new(&mut self.get_mut().0), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().0), cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().0), cx)
        }
    }
}
