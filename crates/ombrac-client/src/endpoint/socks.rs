use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ombrac_macros::{error, info};
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
        let ombrac = self.1.clone();

        info!("SOCKS server listening on {}", self.0.local_addr()?);

        while let Ok((request, mut stream)) = self.0.accept().await {
            let ombrac = ombrac.clone();

            tokio::spawn(async move {
                info!("SOCKS Accept {:?}", request);

                let result = match request {
                    Request::Connect(addr) => {
                        Self::handle_connect(addr, &ombrac, &mut stream).await
                    }
                    #[cfg(feature = "datagram")]
                    Request::Associate(addr) => {
                        Self::handle_associate(addr, &ombrac, &mut stream).await
                    }

                    _ => {
                        let _ = stream.write_response(&Response::CommandNotSupported).await;

                        Ok(())
                    }
                };

                if let Err(_error) = result {
                    error!("{}", _error);
                }
            });
        }

        Ok(())
    }

    #[inline]
    async fn handle_connect(
        addr: Address,
        ombrac: &Client<T>,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        use ombrac::address::Address as OmbracAddress;
        use ombrac::io::util::copy_bidirectional;

        stream
            .write_response(&Response::Success(Address::unspecified()))
            .await?;

        let addr = match addr {
            Address::Domain(domian, port) => OmbracAddress::Domain(domian.to_bytes().into(), port),
            Address::IPv4(addr) => OmbracAddress::IPv4(addr),
            Address::IPv6(addr) => OmbracAddress::IPv6(addr),
        };
        
        let addr2 = addr.clone();

        let mut outbound = ombrac.connect(addr).await?;

        let swap = copy_bidirectional(stream, &mut outbound).await?;

        info!(
            "{:?} Send: {}, Receive: {}",
            addr2.format_as_string(),
            swap.0,
            swap.1
        );

        Ok(())
    }

    #[cfg(feature = "datagram")]
    #[inline]
    async fn handle_associate(
        _addr: Address,
        ombrac: &Client<T>,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        use ombrac::address::Address as OmbracAddress;
        use socks_lib::v5::{Domain, UdpPacket};
        use tokio::io::{Error, ErrorKind};
        use tokio::net::UdpSocket;
        use tokio::time::{Duration, timeout};

        let idle_timeout = Duration::from_secs(60);
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = Address::from_socket_addr(socket.local_addr()?);

        stream.write_response(&Response::Success(&addr)).await?;

        let outbound = ombrac.associate().await?;

        let socket_1 = Arc::new(socket);
        let socket_2 = socket_1.clone();
        let datagram_1 = Arc::new(outbound);
        let datagram_2 = datagram_1.clone();

        let mut buf = [0u8; 2048];

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

        let mut handle_1 = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, socket_1.recv_from(&mut buf)).await {
                    Ok(Ok((n, _addr))) => {
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
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // Timeout
                }
            }

            Ok(())
        });

        let mut handle_2 = tokio::spawn(async move {
            loop {
                match timeout(idle_timeout, datagram_2.recv()).await {
                    Ok(Ok((data, addr))) => {
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

        if tokio::try_join!(&mut handle_1, &mut handle_2).is_err() {
            handle_1.abort();
            handle_2.abort();
        };

        Ok(())
    }
}
