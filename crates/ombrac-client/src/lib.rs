use std::{marker::PhantomData, net::SocketAddr};

use ombrac::io::IntoSplit;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

mod macros;
mod socks;

// pub mod endpoint;
pub mod transport;

pub struct Client<T> {
    inner: T,
}

pub struct Config {
    listen: String,
}

impl Config {
    pub fn new(addr: String) -> Self {
        Self { listen: addr }
    }
}

pub struct SocksServer<Client, Stream> {
    config: Config,
    client: Client,
    _stream: PhantomData<Stream>,
}

impl<Client, Stream> SocksServer<Client, Stream> {
    pub fn with(config: Config, client: Client) -> Self {
        Self { config, client, _stream: PhantomData }
    }
}


impl<Client, Stream> SocksServer<Client, Stream>
where
    Client: ombrac::Client<Stream>,
    Stream: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
   pub async fn listen(mut self) {
        let listener = TcpListener::bind(self.config.listen).await.unwrap();

        loop {
            let outbound = self.client.outbound().await.unwrap();

            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(async move {
                        let request = match Self::handler_v5(stream).await {
                            Ok(value) => value,
                            Err(_error) => {
                                error!("{}", _error);
    
                                return;
                            }
                        };
    
                        match request {
                            socks::SocksRequest::TcpConnect(inbound, address) => {
                                Client::warp_tcp(inbound, outbound, address)
                                    .await
                                    .unwrap();
                            }
    
                            socks::SocksRequest::UdpAssociate(tcp_stream, udp_socket) => {}
                        }
                    });
                }
    
                Err(_error) => {
                    error!("failed to accept: {:?}", _error);
                }
            };
        }
    }
}
