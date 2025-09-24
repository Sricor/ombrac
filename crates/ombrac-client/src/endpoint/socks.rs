use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use socks_lib::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use socks_lib::v5::server::Handler;
use socks_lib::v5::{Address as Socks5Address, Request, Response, Stream, UdpPacket};
use tokio::net::UdpSocket;

use ombrac_macros::{debug, error, info, warn};
use ombrac_transport::{Connection, Initiator};

use crate::client::{Client, UdpSession};

pub struct CommandHandler<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
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
        info!("SOCKS: Handling CONNECT to {}", address);
        let addr = util::socks_to_ombrac_addr(address)?;
        let mut outbound = self.client.open_bidirectional(addr).await?;
        ombrac_transport::io::copy_bidirectional(stream, &mut outbound).await
    }

    /// Handles the SOCKS5 UDP ASSOCIATE command.
    async fn handle_associate(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin + Send>,
    ) -> io::Result<()> {
        info!("SOCKS: Handling UDP ASSOCIATE from {}", stream.peer_addr());

        // 1. 创建一个 ombrac UDP 会话，用于通过隧道转发所有流量。
        let udp_session = self.client.connect_udp();

        // 2. 在本地创建一个 UDP Socket，用于接收来自 SOCKS 客户端的数据。
        //    这个 Socket 的地址将作为响应发送给 SOCKS 客户端。
        let relay_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let relay_addr = SocketAddr::new(
            stream.local_addr().ip(),
            relay_socket.local_addr().unwrap().port(),
        );
        info!("SOCKS: UDP relay listening on {}", relay_addr);

        // 3. 将 relay_socket 的地址作为成功响应发送给 SOCKS 客户端。
        let response_addr = Socks5Address::from(relay_addr);
        stream
            .write_response(&Response::Success(&response_addr))
            .await?;

        // 进入转发循环
        self.udp_relay_loop(stream, relay_socket, udp_session).await
    }

    /// The main relay loop for a UDP association.
    ///
    /// This loop concurrently handles two data flows:
    /// - SOCKS Client -> Relay Socket -> ombrac Tunnel -> Destination
    /// - Destination -> ombrac Tunnel -> Relay Socket -> SOCKS Client
    async fn udp_relay_loop(
        &self,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
        relay_socket: UdpSocket,
        mut udp_session: UdpSession<T, C>,
    ) -> io::Result<()> {
        let mut client_udp_src: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65535]; // Max UDP packet size

        loop {
            tokio::select! {
                // biased; 优先检查控制连接是否关闭
                biased;

                // 1. 检查 TCP 控制连接是否已关闭。
                // 如果是，则关联结束，我们应该退出循环。
                result = stream.read_u8() => {
                    match result {
                        Ok(0) | Err(_) => {
                            info!("SOCKS: TCP control connection for UDP associate closed. Ending session.");
                            return Ok(());
                        }
                        _ => {}
                    }
                }

                // 2. 从 ombrac 隧道接收数据（来自远程目标）
                Some((data, from_addr)) = udp_session.recv_from() => {
                    if let Some(dest) = client_udp_src {
                        debug!("SOCKS: Relaying {} bytes from tunnel (from {}) to SOCKS client {}", data.len(), from_addr, dest);
                        // 将 ombrac 地址转换为 SOCKS 地址
                        let socks_from_addr = util::ombrac_addr_to_socks(from_addr)?;
                        // 创建 SOCKS5 UDP 响应头
                        let udp_response = UdpPacket::un_frag(socks_from_addr, data);
                        // 将封装后的数据包发回给 SOCKS 客户端
                        relay_socket.send_to(&udp_response.to_bytes(), dest).await?;
                    } else {
                        // 如果我们还不知道 SOCKS 客户端的 UDP 地址，就丢弃这个包
                        warn!("SOCKS: Received packet from tunnel before client, discarding.");
                    }
                }

                // 3. 从本地 relay_socket 接收数据（来自 SOCKS 客户端）
                result = relay_socket.recv_from(&mut buf) => {
                    let (len, src) = result?;
                    // 第一次收到包时，记录下 SOCKS 客户端的 UDP 源地址
                    if client_udp_src.is_none() {
                        client_udp_src = Some(src);
                        info!("SOCKS: First UDP packet received from client {}", src);
                    }

                    // 解析 SOCKS5 UDP 请求头
                    let mut bytes = Bytes::copy_from_slice(&buf[..len]);
                    let udp_request = UdpPacket::from_bytes(&mut bytes)?;
                    let payload = udp_request.data;
                    let dest_addr = util::socks_to_ombrac_addr(udp_request.address)?;

                    debug!("SOCKS: Relaying {} bytes from SOCKS client {} to tunnel (for {})", payload.len(), src, dest_addr);
                    // 将裸数据通过 ombrac 会话发送出去
                    udp_session.send_to(payload, dest_addr).await?;
                }
            }
        }
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
                            "SOCKS: Connect to {} finished. Client: {}, Upstream: {} bytes, Downstream: {} bytes",
                            address,
                            stream.peer_addr(),
                            up,
                            down
                        );
                    }
                    Err(err) => {
                        if err.kind() != io::ErrorKind::BrokenPipe
                            && err.kind() != io::ErrorKind::ConnectionReset
                        {
                            error!("SOCKS: Connect to {} failed: {}", address, err);
                        }
                        return Err(err);
                    }
                }
            }
            Request::Associate(_) => {
                if let Err(err) = self.handle_associate(stream).await {
                    if err.kind() != io::ErrorKind::BrokenPipe
                        && err.kind() != io::ErrorKind::ConnectionReset
                    {
                        error!(
                            "SOCKS: Associate from {} failed: {}",
                            stream.peer_addr(),
                            err
                        );
                    }
                    return Err(err);
                }
            }
            Request::Bind(_) => {
                warn!("SOCKS: BIND command is not supported.");
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
