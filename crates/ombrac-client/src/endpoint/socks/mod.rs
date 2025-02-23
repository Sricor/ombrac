mod v5;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use ombrac::prelude::*;
use ombrac_macros::{info, try_or_return};
use ombrac_transport::Transport;
use tokio::net::{TcpListener, TcpStream};

use crate::Client;

pub struct Server {}

pub enum Request {
    TcpConnect(TcpStream, Address),
}

impl Server {
    pub async fn listen<T>(addr: SocketAddr, ombrac: Client<T>) -> Result<(), Box<dyn Error>>
    where
        T: Transport + Send + Sync + 'static,
    {
        use ombrac::io::util::copy_bidirectional;

        let ombrac = Arc::new(ombrac);
        let listener = TcpListener::bind(addr).await?;

        info!("SOCKS server listening on {}", listener.local_addr()?);

        while let Ok((stream, _addr)) = listener.accept().await {
            let ombrac = ombrac.clone();

            tokio::spawn(async move {
                let request = try_or_return!(Self::handler_v5(stream).await);

                match request {
                    Request::TcpConnect(mut inbound, addr) => {
                        // TODO: Timeout check
                        let mut outbound = try_or_return!(ombrac.reliable().await);
                        try_or_return!(ombrac.tcp_connect(&mut outbound, addr.clone()).await);

                        let _bytes =
                            try_or_return!(copy_bidirectional(&mut inbound, &mut outbound).await);

                        info!(
                            "TCP Connect {:?} Send {}, Receive {}",
                            addr, _bytes.0, _bytes.1
                        );
                    }
                };
            });
        }

        Ok(())
    }
}
