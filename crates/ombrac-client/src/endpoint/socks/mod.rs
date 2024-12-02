mod v5;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use ombrac::io::IntoSplit;
use ombrac::request::Address;

use ombrac::Provider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::Client;
use crate::{error, info};

pub struct Server {}

pub enum Request {
    TcpConnect(TcpStream, Address)
}

impl Server {
    pub async fn listen<T, S>(
        addr: SocketAddr,
        ombrac: Client<T>,
    ) -> Result<(), Box<dyn Error>>
    where
        T: Provider<Item = S> + Send + 'static,
        S: IntoSplit + AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    {
        let listener = TcpListener::bind(addr).await?;
        let ombrac = Arc::new(Mutex::new(ombrac));

        while let Ok((stream, _addr)) = listener.accept().await {
            let ombrac = ombrac.clone();

            tokio::spawn(async move {
                let request = match Self::handler_v5(stream).await {
                    Ok(value) => value,
                    Err(_error) => {
                        error!("{_error}");

                        return;
                    }
                };

                match request {
                    Request::TcpConnect(mut inbound, address) => {
                        info!("TcpConnect {:?}", address);

                        let mut outbound = {
                            let mut o = ombrac.lock().await;
                            match o.tcp_connect(address.clone()).await {
                                Ok(value) => value,
                                Err(_error) => {
                                    error!("{_error}");

                                    return;
                                }
                            }
                        };

                        match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                            Ok(value) => {
                                info!("TcpConnect {:?} send {}, receive {}", address, value.0, value.1);
                            },
                            
                            Err(_error) => {
                                error!("TcpConnect {:?} error, {}", address, _error);

                                return;
                            }
                        }
                    }
                };
            });
        };

        Ok(())
    }
}
