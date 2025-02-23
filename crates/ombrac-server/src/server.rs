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

    async fn handle_reliable(stream: &mut impl Reliable, secret: Secret) -> io::Result<()> {
        let request = Connect::from_async_read(stream).await?;

        if request.secret != secret {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Secret does not match",
            ));
        }

        Self::handle_tcp_connect(stream, request.address).await
    }

    async fn handle_unreliable(stream: &mut impl Unreliable, secret: Secret) -> io::Result<()> {
        Self::handle_udp_associate(stream, secret).await
    }

    async fn handle_tcp_connect<A>(stream: &mut impl Reliable, addr: A) -> io::Result<()>
    where
        A: Into<Address>,
    {
        let addr = addr.into().to_socket_addr().await?;
        let mut outbound = TcpStream::connect(addr).await?;

        ombrac::io::util::copy_bidirectional(stream, &mut outbound).await?;

        Ok(())
    }

    pub async fn handle_udp_associate(
        stream: &mut impl Unreliable,
        secret: Secret,
    ) -> io::Result<()> {
        let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(local).await?;

        let mut buf = BytesMut::new();

        // let socks = Arc::new(socket);

        // tokio::spawn(async move {
        //     while let Ok(mut packet) = stream.recv().await {
        //         let packet = Packet::from_bytes(&mut packet)?;

        //         if packet.secret != secret {
        //             return Err(io::Error::new(
        //                 io::ErrorKind::PermissionDenied,
        //                 "Secret does not match",
        //             ));
        //         };

        //         socks.send_to(&packet.data, &packet.address.to_socket_addr().await.unwrap()).await;
        //     };

        //     Ok(())
        // });

        // todo!()

        loop {
            tokio::select! {
                packet = stream.recv() => {
                    let mut packet = match packet {
                        Ok(packet) => packet,
                        Err(e) => return Err(io::Error::other(e.to_string()))
                    };

                    let packet = Packet::from_bytes(&mut packet)?;

                    if packet.secret != secret {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Secret does not match",
                        ));
                    }

                    let target = match packet.address.to_socket_addr().await {
                        Ok(value) => value,
                        Err(e) => return Err(io::Error::other(e.to_string()))
                    };

                    socket.send_to(&packet.data, target).await?;
                },

                result = socket.recv_from(&mut buf) => {
                    let (len, target_addr) = result?;
                    let data = buf[..len].to_vec();
                    let packet = Packet::with(secret, target_addr, data);

                    if let Err(e) = stream.send(packet.to_bytes()?).await {
                        return Err(io::Error::other(e.to_string()))
                    }
                },
            }
        }
    }

    pub async fn listen(&self) -> io::Result<()> {
        let secret = self.secret.clone();

        loop {
            tokio::select! {
                result = self.transport.reliable() => {
                    match result {
                        Ok(mut stream) => {
                            tokio::spawn(async move {
                                if let Err(_error) = Self::handle_reliable(&mut stream, secret).await {
                                    error!("{_error}");
                                }
                            })
                        },
                        Err(err) => return Err(io::Error::other(err.to_string()))
                    };
                }

                result = self.transport.unreliable() => {
                    match result {
                        Ok(mut stream) => {
                            tokio::spawn(async move {
                                if let Err(_error) = Self::handle_unreliable(&mut stream, secret).await {
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
