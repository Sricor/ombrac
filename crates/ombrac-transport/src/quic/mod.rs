pub mod client;
pub mod server;

pub struct Connection(tokio::sync::mpsc::Receiver<Stream>);
pub struct Stream(quinn::SendStream, quinn::RecvStream);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

impl ombrac::Provider for Connection {
    type Item = Stream;

    async fn fetch(&mut self) -> Option<Self::Item> {
        self.0.recv().await
    }
}

mod impl_tokio_io {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::Stream;

    impl AsyncRead for Stream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.get_mut().1), cx, buf)
        }
    }

    impl AsyncWrite for Stream {
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
