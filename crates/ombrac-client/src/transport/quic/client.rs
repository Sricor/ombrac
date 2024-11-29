use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;

use crate::Client;
use crate::{error, info};

use super::Config;

pub mod impl_s2n_quic {
    use s2n_quic::client::Connect;
    use s2n_quic::stream::BidirectionalStream as Stream;
    use s2n_quic::Connection;

    use super::*;

    pub struct NoiseClient {
        config: Config,
        connection: Connection,
    }

    impl NoiseClient {
        async fn stream(&mut self) -> Option<Stream> {
            loop {
                let stream = match self.connection.open_bidirectional_stream().await {
                    Ok(stream) => stream,
                    Err(_error) => {
                        error!(
                            "connection {} failed to open bidirectional stream. {}",
                            self.connection.id(),
                            _error
                        );

                        self.connection = match connection_with_config(&self.config).await {
                            Ok(connection) => {
                                info!(
                                    "{:?} establish connection {} with {:?}",
                                    connection.local_addr(),
                                    connection.id(),
                                    connection.remote_addr()
                                );

                                connection
                            }

                            Err(_error) => {
                                error!("{_error}");

                                continue;
                            }
                        };

                        continue;
                    }
                };

                return Some(stream);
            }
        }
    }

    impl ombrac::Client<Stream> for Client<NoiseClient> {
        async fn outbound(&mut self) -> Option<Stream> {
            self.inner.stream().await
        }
    }

    impl Client<NoiseClient> {
        pub async fn with(config: Config) -> Result<Self, Box<dyn Error>> {
            let connection = connection_with_config(&config).await?;

            Ok(Self {
                inner: NoiseClient { config, connection },
            })
        }
    }

    async fn connection_with_config(config: &Config) -> Result<Connection, Box<dyn Error>> {
        use s2n_quic::provider::congestion_controller;
        use s2n_quic::provider::limits;

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

        let controller = {
            let mut controller = congestion_controller::bbr::Builder::default();

            if let Some(value) = config.initial_congestion_window {
                controller = controller.with_initial_congestion_window(value);
            }

            controller.build()
        };

        let server_name = config.server_name()?;
        let server_socket_address = config.server_socket_address().await?;

        let bind_address = match &config.bind {
            Some(value) => value,
            None => match server_socket_address {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            },
        };

        let client = s2n_quic::Client::builder()
            .with_io(bind_address)?
            .with_limits(limits)?
            .with_congestion_controller(controller)?;

        let client = match &config.tls_cert {
            Some(path) => client.with_tls(Path::new(path))?.start()?,
            None => client.start()?,
        };

        let connect = Connect::new(server_socket_address).with_server_name(server_name);

        let mut connection = match client.connect(connect).await {
            Ok(value) => value,
            Err(error) => {
                return Err(format!(
                    "{} failed to establish connection with {}, {}. {}",
                    client.local_addr()?,
                    server_name,
                    server_socket_address,
                    error
                )
                .into());
            }
        };

        if let Err(error) = connection.keep_alive(true) {
            return Err(format!(
                "failed to keep alive the connection {}. {}",
                connection.id(),
                error
            )
            .into());
        }

        Ok(connection)
    }
}
