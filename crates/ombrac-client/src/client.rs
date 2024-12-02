use std::io;

use ombrac::io::{AsyncReadExt, AsyncWriteExt, IntoSplit, Streamable};
use ombrac::request::{Address, Request};
use ombrac::Provider;

pub struct Client<T> {
    transport: T,
}

impl<Transport, Stream> Client<Transport>
where
    Transport: Provider<Item = Stream>,
    Stream: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    async fn outbound(&mut self) -> io::Result<Stream> {
        match self.transport.fetch().await {
            Some(value) => Ok(value),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Not outbound connected",
            )),
        }
    }

    pub async fn tcp_connect(&mut self, address: Address) -> io::Result<Stream> {
        let mut outbound = self.outbound().await?;
        <Request as Streamable>::write(&Request::TcpConnect(address), &mut outbound).await?;

        Ok(outbound)
    }
}
