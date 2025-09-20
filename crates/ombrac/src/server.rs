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
