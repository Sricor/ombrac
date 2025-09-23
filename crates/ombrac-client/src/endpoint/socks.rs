use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socks_lib::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use socks_lib::v5::server::Handler;
use socks_lib::v5::{Address as Socks5Address, Request, Response, Stream, UdpPacket};
use tokio::net::UdpSocket;

use ombrac_macros::{debug, error, info, warn};
use ombrac_transport::{Connection, Initiator};

use crate::client::Client;

pub struct CommandHandler<T, C> {
    client: Arc<Client<T, C>>,
}

impl<T, C> CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    pub fn new(client: Arc<Client<T, C>>) -> Self {
        Self { client }
    }

    async fn handle_connect(
        &self,
        address: Socks5Address,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<(u64, u64)> {
        let addr = util::socks_to_ombrac_addr(address)?;
        let mut outbound = self.client.open_bidirectional(addr).await?;
        ombrac_transport::io::copy_bidirectional(stream, &mut outbound).await
    }

    async fn handle_associate(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<()> {
        let inbound_udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let inbound_addr = inbound_udp.local_addr()?;

        let reply_addr = SocketAddr::new(stream.local_addr().ip(), inbound_addr.port());
        let bind_addr = Socks5Address::from(reply_addr);
        stream
            .write_response(&Response::Success(&bind_addr))
            .await?;

        info!(
            "SOCKS UDP association created for {}. Client should send UDP to {}",
            stream.peer_addr(),
            bind_addr
        );

        let idle_timeout = Duration::from_secs(120);

        let mut buf = vec![0u8; 65535];
        let (_len, client_udp_addr) =
            match tokio::time::timeout(idle_timeout, inbound_udp.recv_from(&mut buf)).await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    info!(
                        "SOCKS UDP association for {} timed out waiting for first packet.",
                        stream.peer_addr()
                    );
                    return Ok(());
                }
            };

        info!(
            "Received first UDP packet from client at {}",
            client_udp_addr
        );

        let client_clone = Arc::clone(&self.client);
        let inbound_udp_clone = Arc::clone(&inbound_udp);

        let remote_to_client = tokio::spawn(async move {
            loop {
                match client_clone.read_datagram().await {
                    Ok((origin_addr, data)) => {
                        let response_packet = UdpPacket::un_frag(
                            util::ombrac_addr_to_socks(origin_addr).unwrap(),
                            data,
                        );
                        if let Err(_e) = inbound_udp_clone
                            .send_to(&response_packet.to_bytes(), client_udp_addr)
                            .await
                        {
                            error!(
                                "Failed to send UDP packet to SOCKS client {}: {}",
                                client_udp_addr, _e
                            );
                            break;
                        }
                    }
                    Err(_e) => {
                        error!("Error reading datagram from ombrac client: {}", _e);
                        break;
                    }
                }
            }
        });

        let client = self.client.clone();
        let client_to_remote = tokio::spawn(async move {
            if let Err(e) = Self::process_client_packet(&client, &buf[.._len]).await {
                error!("Error processing first UDP packet: {}", e);
                return;
            }

            loop {
                match inbound_udp.recv_from(&mut buf).await {
                    Ok((len, src_addr)) => {
                        if src_addr != client_udp_addr {
                            warn!(
                                "Received UDP packet from unexpected source {}, expected {}. Ignoring.",
                                src_addr, client_udp_addr
                            );
                            continue;
                        }
                        if let Err(e) = Self::process_client_packet(&client, &buf[..len]).await {
                            error!("Error processing UDP packet from client: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error receiving from SOCKS UDP socket: {}", e);
                        break;
                    }
                }
            }
        });

        let mut tcp_check_buf = [0u8; 1];
        tokio::select! {
            _ = stream.read(&mut tcp_check_buf) => {
                info!("SOCKS TCP control connection for {} closed, ending UDP association.", stream.peer_addr());
            },
            _ = remote_to_client => {
                info!("Ombrac->Client UDP task finished for {}.", stream.peer_addr());
            },
            _ = client_to_remote => {
                info!("Client->Ombrac UDP task finished for {}.", stream.peer_addr());
            },
        }

        info!("[UDP] Association for {} ended.", stream.peer_addr());
        Ok(())
    }

    async fn process_client_packet(client: &Client<T, C>, raw: &[u8]) -> io::Result<()> {
        let pkt = UdpPacket::from_bytes(&mut &raw[..]).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse SOCKS UDP packet: {e}"),
            )
        })?;

        if pkt.frag != 0 {
            warn!("Dropping fragmented SOCKS5 UDP packet, which is not supported.");
            return Ok(());
        }

        let dest_addr = util::socks_to_ombrac_addr(pkt.address)?;
        client.send_datagram(dest_addr, pkt.data).await
    }
}

impl<T, C> Handler for CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    async fn handle<S>(&self, stream: &mut Stream<S>, request: Request) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!("SOCKS Request: {:?}", request);

        match request {
            Request::Connect(address) => {
                stream.write_response_unspecified().await?;

                match self.handle_connect(address.clone(), stream).await {
                    Ok((up, down)) => {
                        info!(
                            "{} Connect {}, Send: {}, Recv: {}",
                            stream.peer_addr(),
                            address,
                            up,
                            down
                        );
                    }
                    Err(err) => {
                        error!("SOCKS connect to {} failed: {}", address, err);
                        return Err(err);
                    }
                }
            }
            Request::Associate(_) => {
                self.handle_associate(stream).await?
            }
            _ => {
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

mod util {
    use ombrac::protocol::Address as OmbracAddress;
    use socks_lib::v5::Address as Socks5Address;
    use std::io;

    pub(super) fn socks_to_ombrac_addr(addr: Socks5Address) -> io::Result<OmbracAddress> {
        let result = match addr {
            Socks5Address::IPv4(value) => OmbracAddress::SocketV4(value),
            Socks5Address::IPv6(value) => OmbracAddress::SocketV6(value),
            Socks5Address::Domain(domain, port) => {
                OmbracAddress::Domain(domain.as_bytes().to_owned(), port)
            }
        };

        Ok(result)
    }

    pub(super) fn ombrac_addr_to_socks(addr: OmbracAddress) -> io::Result<Socks5Address> {
        let result = match addr {
            OmbracAddress::SocketV4(sa) => Socks5Address::IPv4(sa),
            OmbracAddress::SocketV6(sa) => Socks5Address::IPv6(sa),
            OmbracAddress::Domain(domain_bytes, port) => {
                Socks5Address::Domain(domain_bytes.try_into()?, port)
            }
        };

        Ok(result)
    }
}
