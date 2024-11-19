use std::{error::Error, net::SocketAddr};

use ombrac_protocol::Provider;
use tokio::sync::mpsc::Receiver;

use super::{connection, stream, Config};

pub mod impl_s2n_quic {
    use std::path::Path;
    use std::time::Duration;

    use s2n_quic::provider::congestion_controller;
    use s2n_quic::provider::limits;
    use s2n_quic::stream::BidirectionalStream;
    use s2n_quic::client::{Client, Connect};

    use connection::impl_s2n_quic::connection;
    use stream::impl_s2n_quic::stream;
    use tokio::sync::mpsc;

    use super::*;

    pub struct NoiseQuic {
        stream: Receiver<BidirectionalStream>,
    }

    impl Provider<BidirectionalStream> for NoiseQuic {
        async fn fetch(&mut self) -> Option<BidirectionalStream> {
            self.stream.recv().await
        }
    }

    impl NoiseQuic {
        pub async fn with(config: Config) -> Result<Self, Box<dyn Error>> {
            let limits = {
                let mut limits = limits::Limits::new();

                if let Some(value) = config.bidirectional_local_data_window {
                    limits = limits.with_bidirectional_local_data_window(value)?;
                }

                if let Some(value) = config.bidirectional_remote_data_window {
                    limits = limits.with_bidirectional_remote_data_window(value)?;
                }

                if let Some(value) = config.max_open_bidirectional_streams {
                    limits = limits.with_max_open_local_bidirectional_streams(value)?;
                }

                if let Some(value) = config.max_open_bidirectional_streams {
                    limits = limits.with_max_open_remote_bidirectional_streams(value)?;
                }

                if let Some(value) = config.max_handshake_duration {
                    limits = limits.with_max_handshake_duration(value)?;
                }

                if let Some(value) = config.max_keep_alive_period {
                    limits = limits.with_max_keep_alive_period(value)?;
                }

                if let Some(value) = config.max_idle_timeout {
                    limits = limits.with_max_idle_timeout(value)?;
                }

                limits
            };



            let (sender, receiver) = mpsc::channel(1);

            tokio::spawn(async move {
                loop {
                    let controller = {
                        let mut controller = congestion_controller::bbr::Builder::default();
        
                        if let Some(value) = config.initial_congestion_window {
                            controller = controller.with_initial_congestion_window(value);
                        }
        
                        controller.build()
                    };

                    let (bind_address, server_address, server_name) = resolve_address(&config).unwrap();
    
                    let connect = Connect::new(server_address).with_server_name(server_name);
    
                    let client = Client::builder()
                        .with_io(bind_address).unwrap()
                        .with_limits(limits).unwrap()
                        .with_congestion_controller(controller).unwrap();
    
                    let client = match &config.tls_cert {
                        Some(path) => client.with_tls(Path::new(path)).unwrap().start().unwrap(),
                        None => client.start().unwrap(),
                    };

                    let mut connection = client.connect(connect).await.unwrap();

                    let stream = connection.accept_bidirectional_stream().await.unwrap().unwrap();

                    if sender.send(stream).await.is_err() {
                        break;
                    }
                }
            });

            Ok(Self { stream: receiver })
        }
    }
}

fn resolve_address(cfg: &Config) -> Result<(SocketAddr, SocketAddr, String), Box<dyn Error>> {
    use std::net::SocketAddr;
    use std::net::ToSocketAddrs;

    let pos = cfg.server_address.rfind(':').ok_or(format!("invalid address {}", cfg.server_address))?;

    let server_name = match cfg.server_name.clone() {
        Some(value) => value,
        None => {
            String::from(&cfg.server_address[..pos])
        }
    };

    let server_address = cfg.server_address
        .to_socket_addrs()?
        .nth(0)
        .ok_or(format!("unable to resolve address {}", cfg.server_address))?;

    let bind_address = match cfg.bind {
        Some(value) => value,
        None => {
            let address = match server_address {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            address.parse().expect("failed to parse socket address")
        }
    };

    Ok((bind_address, server_address, server_name))
}
