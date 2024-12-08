use std::future::Future;
use std::io;

use bytes::BytesMut;

pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

pub mod util {
    use super::*;

    /// Copies data bidirectionally between two objects that implement AsyncRead and AsyncWrite.
    ///
    /// This function will read from both `a` and `b` and write the data to the other side until
    /// EOF is reached on both sides.
    ///
    /// # Arguments
    ///
    /// * `a` - The first stream
    /// * `b` - The second stream
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(a_to_b_bytes, b_to_a_bytes)` indicating the number of bytes copied in each direction
    ///
    /// # Errors
    ///
    /// This function will return an error if any read or write operation fails.
    pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        const DEFAULT_BUF_SIZE: usize = 8 * 1024;

        let mut buffer1 = [0u8; DEFAULT_BUF_SIZE];
        let mut buffer2 = [0u8; DEFAULT_BUF_SIZE];

        let mut a_to_b_done = false;
        let mut b_to_a_done = false;

        let mut a_to_b_bytes = 0u64;
        let mut b_to_a_bytes = 0u64;

        loop {
            if a_to_b_done && b_to_a_done {
                break;
            }

            tokio::select! {
                result = a.read(&mut buffer1) => {
                    let size = match result {
                        Ok(0) => {
                            a_to_b_done = true;
                            continue;
                        },
                        Ok(num) => num,
                        Err(err) => return Err(err),
                    };

                    b.write_all(&buffer1[..size]).await?;
                    b.flush().await?;

                    a_to_b_bytes += size as u64;
                },

                result = b.read(&mut buffer2) => {
                    let size = match result {
                        Ok(0) => {
                            b_to_a_done = true;
                            continue;
                        },
                        Ok(num) => num,
                        Err(err) => return Err(err),
                    };

                    a.write_all(&buffer2[..size]).await?;
                    a.flush().await?;

                    b_to_a_bytes += size as u64;
                }
            }
        }

        Ok((a_to_b_bytes, b_to_a_bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{self, AsyncRead, AsyncWrite};

        struct MockStream {
            read_data: Vec<u8>,
            written_data: Vec<u8>,
            read_pos: usize,
        }

        impl MockStream {
            fn new(read_data: Vec<u8>) -> Self {
                Self {
                    read_data,
                    written_data: Vec::new(),
                    read_pos: 0,
                }
            }

            fn written_data(&self) -> &[u8] {
                &self.written_data
            }
        }

        impl AsyncRead for MockStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.read_pos >= self.read_data.len() {
                    return Poll::Ready(Ok(()));
                }

                let remaining = &self.read_data[self.read_pos..];
                let n = std::cmp::min(buf.remaining(), remaining.len());
                buf.put_slice(&remaining[..n]);
                self.read_pos += n;
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for MockStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.written_data.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl Unpin for MockStream {}

        struct ErrorStream;

        impl AsyncRead for ErrorStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "Mock read error")))
            }
        }

        impl AsyncWrite for ErrorStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Mock write error",
                )))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl Unpin for ErrorStream {}

        #[tokio::test]
        async fn test_basic_bidirectional_copy() -> io::Result<()> {
            let mut stream1 = MockStream::new(b"Hello".to_vec());
            let mut stream2 = MockStream::new(b"World".to_vec());

            copy_bidirectional(&mut stream1, &mut stream2).await?;

            assert_eq!(stream1.written_data(), b"World");
            assert_eq!(stream2.written_data(), b"Hello");
            Ok(())
        }

        #[tokio::test]
        async fn test_empty_streams() -> io::Result<()> {
            let mut stream1 = MockStream::new(vec![]);
            let mut stream2 = MockStream::new(vec![]);

            copy_bidirectional(&mut stream1, &mut stream2).await?;

            assert!(stream1.written_data().is_empty());
            assert!(stream2.written_data().is_empty());
            Ok(())
        }

        #[tokio::test]
        async fn test_large_data_copy() -> io::Result<()> {
            let large_data1: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();
            let large_data2: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).rev().collect();

            let mut stream1 = MockStream::new(large_data1.clone());
            let mut stream2 = MockStream::new(large_data2.clone());

            copy_bidirectional(&mut stream1, &mut stream2).await?;

            assert_eq!(stream1.written_data(), large_data2);
            assert_eq!(stream2.written_data(), large_data1);
            Ok(())
        }

        #[tokio::test]
        async fn test_uneven_data_sizes() -> io::Result<()> {
            let mut stream1 = MockStream::new(b"Short".to_vec());
            let mut stream2 = MockStream::new(b"This is a longer message".to_vec());

            copy_bidirectional(&mut stream1, &mut stream2).await?;

            assert_eq!(stream1.written_data(), b"This is a longer message");
            assert_eq!(stream2.written_data(), b"Short");
            Ok(())
        }

        #[tokio::test]
        async fn test_error_handling() {
            let mut stream1 = MockStream::new(b"Data".to_vec());
            let mut stream2 = ErrorStream;

            let result = copy_bidirectional(&mut stream1, &mut stream2).await;
            assert!(result.is_err());

            if let Err(e) = result {
                assert_eq!(e.kind(), io::ErrorKind::Other);
            }
        }

        #[tokio::test]
        async fn test_byte_counts() -> io::Result<()> {
            let mut stream1 = MockStream::new(b"Hello".to_vec());
            let mut stream2 = MockStream::new(b"World".to_vec());

            let (a_to_b, b_to_a) = copy_bidirectional(&mut stream1, &mut stream2).await?;

            assert_eq!(a_to_b, 5);
            assert_eq!(b_to_a, 5);
            Ok(())
        }

        #[tokio::test]
        async fn test_error_mid_copy() -> io::Result<()> {
            struct ErrorAfterStream {
                data: Vec<u8>,
                read_pos: usize,
                error_after: usize,
                written_data: Vec<u8>,
            }

            impl ErrorAfterStream {
                fn new(data: Vec<u8>, error_after: usize) -> Self {
                    Self {
                        data,
                        read_pos: 0,
                        error_after,
                        written_data: Vec::new(),
                    }
                }
            }

            impl AsyncRead for ErrorAfterStream {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &mut tokio::io::ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    if self.read_pos >= self.error_after {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Planned error",
                        )));
                    }

                    let available = std::cmp::min(
                        self.data.len() - self.read_pos,
                        self.error_after - self.read_pos,
                    );

                    if available == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    let n = std::cmp::min(buf.remaining(), available);
                    buf.put_slice(&self.data[self.read_pos..self.read_pos + n]);
                    self.read_pos += n;
                    Poll::Ready(Ok(()))
                }
            }

            impl AsyncWrite for ErrorAfterStream {
                fn poll_write(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    self.written_data.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            impl Unpin for ErrorAfterStream {}

            // Test case 1: Error while reading
            {
                let mut stream1 = ErrorAfterStream::new(b"Hello World".to_vec(), 5);
                let mut stream2 = ErrorAfterStream::new(b"Test Data".to_vec(), 100);

                let result = copy_bidirectional(&mut stream1, &mut stream2).await;
                assert!(result.is_err());
                if let Err(e) = result {
                    assert_eq!(e.kind(), io::ErrorKind::Other);
                    assert_eq!(e.to_string(), "Planned error");
                }
                assert_eq!(stream2.written_data, b"Hello");
            }

            // Test case 2: Verify bidirectional behavior with error
            {
                let mut stream1 = ErrorAfterStream::new(b"Hello World".to_vec(), 5);
                let mut stream2 = ErrorAfterStream::new(b"Test Data".to_vec(), 7);

                let result = copy_bidirectional(&mut stream1, &mut stream2).await;
                assert!(result.is_err());
                // The error could come from either stream depending on timing
                if let Err(e) = result {
                    assert_eq!(e.kind(), io::ErrorKind::Other);
                    assert_eq!(e.to_string(), "Planned error");
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_flush_error() -> io::Result<()> {
            struct FlushErrorStream {
                inner: MockStream,
            }

            impl AsyncRead for FlushErrorStream {
                fn poll_read(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &mut tokio::io::ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
                }
            }

            impl AsyncWrite for FlushErrorStream {
                fn poll_write(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
                }

                fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "Flush error")))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
                }
            }

            impl Unpin for FlushErrorStream {}

            let mut stream1 = MockStream::new(b"Hello".to_vec());
            let mut stream2 = FlushErrorStream {
                inner: MockStream::new(b"World".to_vec()),
            };

            let result = copy_bidirectional(&mut stream1, &mut stream2).await;
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(e.kind(), io::ErrorKind::Other);
                assert_eq!(e.to_string(), "Flush error");
            }

            Ok(())
        }
    }
}
