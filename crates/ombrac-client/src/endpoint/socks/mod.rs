mod v5;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ombrac::request::Address;
use ombrac::Provider;
use ombrac_macros::{error, info, try_or_return};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use crate::Client;

pub struct Server {}

pub enum Request {
    TcpConnect(TcpStream, Address),
}


impl Server {
    pub async fn listen<T, S>(addr: SocketAddr, ombrac: Client<T>) -> Result<(), Box<dyn Error>>
    where
        T: Provider<Item = S> + Send + Sync + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        use ombrac::io::util::copy_bidirectional;

        const INITIAL_TIMEOUT: Duration = Duration::from_secs(5);
        const MAX_RETRIES: usize = 3;
        const BACKOFF_MULTIPLIER: u32 = 2;

        let ombrac = Arc::new(ombrac);
        let listener = TcpListener::bind(addr).await?;

        info!("SOCKS server listening on {}", listener.local_addr()?);

        while let Ok((stream, _addr)) = listener.accept().await {
            let ombrac = ombrac.clone();

            tokio::spawn(async move {
                let request = try_or_return!(Self::handler_v5(stream).await);

                match request {
                    Request::TcpConnect(mut inbound, addr) => {
                        let mut retries = 0;
                        let mut current_timeout = INITIAL_TIMEOUT;

                        let mut outbound = loop {
                            let connect_result = timeout(current_timeout, ombrac.tcp_connect(addr.clone())).await;

                            match connect_result {
                                Ok(Ok(conn)) => break conn,
                                Ok(Err(error)) => {
                                    if retries >= MAX_RETRIES {
                                        error!("Failed to connect after {retries} retries: {error}");
                                        return;
                                    }
                                }
                                Err(_elapsed) => {
                                    if retries >= MAX_RETRIES {
                                        error!("Connection timeout after {} seconds", current_timeout.as_secs());
                                        return;
                                    }
                                    current_timeout *= BACKOFF_MULTIPLIER;
                                }
                            };

                            retries += 1;
                            sleep(Duration::from_millis(100)).await;
                        };

                        let bytes =
                            try_or_return!(copy_bidirectional(&mut inbound, &mut outbound).await);

                        info!(
                            "TCP Connect {:?} Send {}, Receive {}",
                            addr, bytes.0, bytes.1
                        );
                    }
                };
            });
        }

        Ok(())
    }
}
