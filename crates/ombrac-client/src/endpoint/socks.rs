use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ombrac_macros::{debug, error, info};
use ombrac_transport::Initiator;
use socks_lib::v5::server::Server as SocksServer;
use socks_lib::v5::{Address, Request, Response, Stream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Client;

pub struct Server<T: Initiator>(SocksServer, Arc<Client<T>>);

impl<T: Initiator> Server<T> {
    pub async fn bind<A: Into<SocketAddr>>(addr: A, ombrac: Arc<Client<T>>) -> io::Result<Self> {
        Ok(Self(SocksServer::bind(addr.into()).await?, ombrac))
    }

    pub async fn listen(&self) -> io::Result<()> {
        let ombrac = Arc::clone(&self.1);

        info!("SOCKS server listening on {}", self.0.local_addr()?);

        loop {
            match self.0.accept().await {
                Ok((request, mut stream)) => {
                    let ombrac = ombrac.clone();

                    tokio::spawn(async move {
                        let result = match request {
                            Request::Connect(address) => {
                                Self::handle_connect(ombrac, address, stream).await
                            }
                            #[cfg(feature = "datagram")]
                            Request::Associate(address) => {
                                Self::handle_associate(ombrac, address, stream).await
                            }
                            _ => {
                                match stream.write_response(&Response::CommandNotSupported).await {
                                    Ok(_) => Ok(()),
                                    Err(e) => Err(e),
                                }
                            }
                        };

                        if let Err(_error) = result {
                            error!("{}", _error);
                        }
                    });
                }

                Err(_error) => {
                    error!("Failed to accept: {}", _error);
                    continue;
                }
            }
        }
    }

    #[inline]
    async fn handle_connect(
        ombrac: Arc<Client<T>>,
        address: Address,
        mut stream: Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        use ombrac::address::Address as OmbracAddress;

        stream
            .write_response(&Response::Success(Address::unspecified()))
            .await?;

        let addr = match address {
            Address::Domain(domian, port) => OmbracAddress::Domain(domian.to_bytes().into(), port),
            Address::IPv4(addr) => OmbracAddress::IPv4(addr),
            Address::IPv6(addr) => OmbracAddress::IPv6(addr),
        };

        info!("Connect {}", addr);

        let mut outbound = ombrac.connect(addr).await?;

        ombrac::io::util::copy_bidirectional(&mut stream, &mut outbound).await?;

        Ok(())
    }

    #[cfg(feature = "datagram")]
    #[inline]
    async fn handle_associate(
        ombrac: Arc<Client<T>>,
        _address: Address,
        mut stream: Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        use ombrac::address::Address as OmbracAddress;
        use socks_lib::v5::{Domain, UdpPacket};
        use tokio::io::{Error, ErrorKind};
        use tokio::net::UdpSocket;
        use tokio::time::{Duration, timeout};

        const DEFAULT_BUF_SIZE: usize = 2 * 1024;

        let idle_timeout = Duration::from_secs(10);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = Address::from_socket_addr(socket.local_addr()?);

        stream.write_response(&Response::Success(&addr)).await?;
        drop(stream);

        let outbound = ombrac.associate().await?;

        let socket_1 = Arc::new(socket);
        let socket_2 = Arc::clone(&socket_1);
        let datagram_1 = Arc::new(outbound);
        let datagram_2 = Arc::clone(&datagram_1);

        let mut buf = [0u8; DEFAULT_BUF_SIZE];

        // Accpet first client
        let client_addr = {
            let (n, client_addr) = match timeout(idle_timeout, socket_1.recv_from(&mut buf)).await {
                Ok(Ok((n, addr))) => (n, addr),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::TimedOut,
                        "No initial packet received",
                    ));
                }
            };

            let packet = UdpPacket::from_bytes(&mut &buf[..n]).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Failed to parse UDP packet: {}", e),
                )
            })?;

            let addr = match packet.address {
                Address::Domain(domian, port) => {
                    OmbracAddress::Domain(domian.to_bytes().into(), port)
                }
                Address::IPv4(addr) => OmbracAddress::IPv4(addr),
                Address::IPv6(addr) => OmbracAddress::IPv6(addr),
            };

            datagram_1.send(packet.data, addr).await?;

            client_addr
        };

        let handle_1 = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, socket_1.recv_from(&mut buf)).await {
                    Ok(Ok((n, addr))) => {
                        // Only accept packets from the first client
                        if addr != client_addr {
                            buf = [0u8; DEFAULT_BUF_SIZE];
                            continue;
                        }

                        let packet = UdpPacket::from_bytes(&mut &buf[..n]).map_err(|e| {
                            Error::new(
                                ErrorKind::InvalidData,
                                format!("Failed to parse UDP packet: {}", e),
                            )
                        })?;

                        let addr = match packet.address {
                            Address::Domain(domian, port) => {
                                OmbracAddress::Domain(domian.to_bytes().into(), port)
                            }
                            Address::IPv4(addr) => OmbracAddress::IPv4(addr),
                            Address::IPv6(addr) => OmbracAddress::IPv6(addr),
                        };

                        debug!("Associate send to {}, length: {}", addr, packet.data.len());
                        datagram_1.send(packet.data, addr).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // Timeout
                }
            }

            Ok(())
        });

        let handle_2 = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, datagram_2.recv()).await {
                    Ok(Ok((data, addr))) => {
                        debug!("Associate recv from {}, length: {}", addr, data.len());

                        let addr = match addr {
                            OmbracAddress::Domain(domian, port) => {
                                Address::Domain(Domain::from_bytes(domian.to_bytes()), port)
                            }
                            OmbracAddress::IPv4(addr) => Address::IPv4(addr),
                            OmbracAddress::IPv6(addr) => Address::IPv6(addr),
                        };

                        let packet = UdpPacket::un_frag(addr, data);

                        socket_2.send_to(&packet.data, client_addr).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // Timeout
                }
            }

            Ok(())
        });

        tokio::select! {
            result = handle_1 => result?,
            result = handle_2 => result?
        }?;

        Ok(())
    }
}
