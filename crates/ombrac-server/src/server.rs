use std::net::SocketAddr;
use std::{io, sync::Arc};

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

    async fn handle_reliable(stream: impl Reliable, secret: Secret) -> io::Result<()> {
        Self::handle_tcp_connect(stream, secret).await
    }

    async fn handle_unreliable(stream: impl Unreliable, secret: Secret) -> io::Result<()> {
        Self::handle_udp_associate(stream, secret).await
    }

    async fn handle_tcp_connect(mut stream: impl Reliable, secret: Secret) -> io::Result<()> {
        let request = Connect::from_async_read(&mut stream).await?;

        if request.secret != secret {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Secret does not match",
            ));
        }

        let addr = request.address.to_socket_addr().await?;
        let mut target = TcpStream::connect(addr).await?;

        ombrac::io::util::copy_bidirectional(&mut stream, &mut target).await?;

        Ok(())
    }

    async fn handle_udp_associate(stream: impl Unreliable, secret: Secret) -> io::Result<()> {
        const DEFAULT_BUFFER_SIZE: usize = 2 * 1024;

        // TODO: ipv6?
        let local: SocketAddr = "[::]:0".parse().unwrap();
        let socket = UdpSocket::bind(local).await?;

        let sock_send = Arc::new(socket);
        let sock_recv = Arc::clone(&sock_send);
        let stream_send = Arc::new(stream);
        let stream_recv = Arc::clone(&stream_send);

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; DEFAULT_BUFFER_SIZE];

            loop {
                let (len, addr) = sock_recv.recv_from(&mut buf).await?;

                let data = buf[..len].to_vec();
                let packet = Packet::with(secret, addr, data);

                if stream_send.send(packet.to_bytes()?).await.is_err() {
                    break;
                }
            }

            Ok::<(), io::Error>(())
        });

        while let Ok(mut packet) = stream_recv.recv().await {
            let packet = Packet::from_bytes(&mut packet)?;

            if packet.secret != secret {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Secret does not match",
                ));
            };

            let target = packet.address.to_socket_addr().await?;
            sock_send.send_to(&packet.data, target).await?;
        }

        handle.abort();

        Ok(())
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
