// pub mod client;
pub mod request;
// pub mod server;

pub mod io;

use std::io::Result;
use std::net::SocketAddr;
use std::{future::Future, io::Error};

use io::{IntoSplit, Streamable};
use request::{Address, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait Provider<T> {
    fn fetch(&mut self) -> impl Future<Output = Option<T>> + Send;
}

pub trait Client<Stream>: Send
where
    Stream: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    fn outbound(&mut self) -> impl Future<Output = Option<Stream>> + Send;

    fn warp_tcp<S>(
        inbound: S,
        mut outbound: Stream,
        address: Address,
    ) -> impl Future<Output = Result<()>> + Send
    where
        S: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        use crate::io::utils::copy_bidirectional;

        async move {
            <Request as Streamable>::write(&Request::TcpConnect(address), &mut outbound).await?;

            copy_bidirectional(inbound, outbound).await?;

            Ok(())
        }
    }

    fn warp_udp() {}
}

pub trait Server<Stream>: Sized + Send
where
    Stream: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    fn handler(mut stream: Stream) -> impl Future<Output = Result<()>> + Send {
        use crate::io::utils::copy_bidirectional;
        use tokio::net::TcpStream;

        async move {
            let request = <Request as Streamable>::read(&mut stream).await?;

            match request {
                Request::TcpConnect(address) => {
                    let address = Self::resolve(address).await?;
                    let outbound = TcpStream::connect(address).await?;

                    copy_bidirectional(stream, outbound).await?
                }
                _ => todo!(),
            };

            Ok(())
        }
    }

    fn resolve(address: Address) -> impl Future<Output = Result<SocketAddr>> + Send {
        use tokio::net::lookup_host;

        async move {
            match address {
                Address::Domain(domain, port) => lookup_host(format!("{}:{}", domain, port))
                    .await?
                    .next()
                    .ok_or(Error::other(format!(
                        "could not resolve domain '{}:{}'",
                        domain, port
                    ))),
                Address::IPv4(addr) => Ok(SocketAddr::V4(addr)),
                Address::IPv6(addr) => Ok(SocketAddr::V6(addr)),
            }
        }
    }

    fn listen(self) -> impl Future<Output = ()> + Send;
}
