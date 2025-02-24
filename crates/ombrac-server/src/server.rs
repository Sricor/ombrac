use std::net::SocketAddr;
use std::{io, sync::Arc};

use bytes::BytesMut;
use ombrac::prelude::*;
use ombrac_transport::{Reliable, Transport, Unreliable};
use tokio::net::{TcpStream, UdpSocket};

use ombrac_macros::error;

pub struct Server<T> {
    secret: Secret,
    transport: T,
}

impl<T: Transport> Server<T> {
    pub fn new(secret: Secret, transport: T) -> Self {
        Self { secret, transport }
    }

    async fn handle_reliable(mut stream: impl Reliable, secret: Secret) -> io::Result<()> {
        let request = Connect::from_async_read(&mut stream).await?;

        if request.secret != secret {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Secret does not match",
            ));
        }

        Self::handle_tcp_connect(stream, request.address).await
    }

    async fn handle_unreliable(stream: impl Unreliable, secret: Secret) -> io::Result<()> {
        Self::handle_udp_associate(stream, secret).await
    }

    async fn handle_tcp_connect<A>(mut stream: impl Reliable, addr: A) -> io::Result<()>
    where
        A: Into<Address>,
    {
        let addr = addr.into().to_socket_addr().await?;
        let mut outbound = TcpStream::connect(addr).await?;

        ombrac::io::util::copy_bidirectional(&mut stream, &mut outbound).await?;

        Ok(())
    }

    async fn handle_udp_associate(stream: impl Unreliable, secret: Secret) -> io::Result<()> {
        let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(local).await?;

        let socks_1 = Arc::new(socket);
        let socks_2 = socks_1.clone();
        let stream_1 = Arc::new(stream);
        let stream_2 = stream_1.clone();

        tokio::spawn(async move {
            while let Ok(mut packet) = stream_1.recv().await {
                let packet = Packet::from_bytes(&mut packet)?;

                if packet.secret != secret {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Secret does not match",
                    ));
                };

                let target = packet.address.to_socket_addr().await?;
                socks_1.send_to(&packet.data, target).await?;
            }

            Ok(())
        });

        let mut buf = BytesMut::new();

        loop {
            let (len, addr) = socks_2.clone().recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();
            let packet = Packet::with(secret, addr, data);

            if let Err(e) = stream_2.send(packet.to_bytes()?).await {
                return Err(io::Error::other(e.to_string()));
            }
        }
    }

    pub async fn listen(&self) -> io::Result<()> {
        let secret = self.secret.clone();

        loop {
            tokio::select! {
                result = self.transport.reliable() => {
                    match result {
                        Ok(stream) => {
                            tokio::spawn(async move {
                                if let Err(_error) = Self::handle_reliable(stream, secret).await {
                                    error!("{_error}");
                                }
                            })
                        },
                        Err(err) => return Err(io::Error::other(err.to_string()))
                    };
                }

                result = self.transport.unreliable() => {
                    match result {
                        Ok(stream) => {
                            tokio::spawn(async move {
                                if let Err(_error) = Self::handle_unreliable(stream, secret).await {
                                    error!("{_error}");
                                }
                            })
                        },
                        Err(err) => return Err(io::Error::other(err.to_string()))
                    };
                }
            };
        }
    }
}
