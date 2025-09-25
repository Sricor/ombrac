use std::net::Ipv4Addr;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use futures::{
    stream::{SplitSink, SplitStream},
    {SinkExt, StreamExt},
};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tun_rs::{
    AsyncDevice,
    async_framed::{BytesCodec, DeviceFramed},
};

use ombrac::protocol::Address;
use ombrac_macros::{debug, error, info};
use ombrac_netstack::*;
use ombrac_transport::{Connection, Initiator};

use crate::{client::Client, endpoint::tun::fakedns::FakeDns};

// 为每个 UDP 流定义一个超时时间
const UDP_STREAM_TIMEOUT: Duration = Duration::from_secs(60);

mod fakedns {
    use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{atomic::{AtomicU32, Ordering}, Arc}, time::Duration};

    use bytes::Bytes;
    use hickory_proto::{op::{Message, MessageType, ResponseCode}, rr::{Name, RData, Record, RecordType}};
    use moka::future::Cache;
    use ombrac_macros::{info, warn};

    #[derive(Clone)]
    pub struct FakeDns {
        ip_range: Ipv4Addr,
        // 优化：使用原子类型替代 Mutex，实现无锁 IP 生成
        next_ip_offset: Arc<AtomicU32>,
        domain_to_ip: Cache<Name, Ipv4Addr>,
        ip_to_domain: Cache<Ipv4Addr, Name>,
    }

    impl FakeDns {
        pub fn new(start_ip: Ipv4Addr) -> Self {
            Self {
                ip_range: start_ip,
                next_ip_offset: Arc::new(AtomicU32::new(0)),
                domain_to_ip: Cache::builder()
                    .max_capacity(10_000)
                    .time_to_live(Duration::from_secs(30)) // 例如，设置一小时的 TTL
                    .build(),
                ip_to_domain: Cache::builder()
                    .max_capacity(10_000)
                    .time_to_live(Duration::from_secs(30))
                    .build(),
            }
        }

        // 生成下一个可用的伪造 IP (同步、无锁)
        fn get_next_ip(&self) -> Ipv4Addr {
            // 使用 fetch_add 实现原子性递增，Ordering::SeqCst 提供最强的内存一致性保证
            let offset = self.next_ip_offset.fetch_add(1, Ordering::SeqCst);

            // 将无限增长的 offset 映射到 1-254 的范围
            let last_octet = (offset % 254) + 1;

            let ip_bytes = self.ip_range.octets();
            Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], last_octet as u8)
        }

        // 核心功能：处理 DNS 查询
        pub async fn handle_dns_query(&self, query_bytes: &[u8]) -> Option<Message> {
            let query = match Message::from_vec(query_bytes) {
                Ok(q) => q,
                Err(e) => {
                    warn!("Failed to parse DNS query: {}", e);
                    return None;
                }
            };

            if query.queries().is_empty() {
                return None;
            }

            let question = &query.queries()[0];
            let domain_name = question.name();

            if question.query_type() != RecordType::A {
                let mut response = query.clone();
                response.set_message_type(MessageType::Response);
                response.set_response_code(ResponseCode::Refused);
                return Some(response);
            }

            let fake_ip = if let Some(ip) = self.domain_to_ip.get(domain_name).await {
                ip
            } else {
                // get_next_ip 现在是同步函数，无需 .await
                let new_ip = self.get_next_ip();
                self.domain_to_ip.insert(domain_name.clone(), new_ip).await;
                self.ip_to_domain.insert(new_ip, domain_name.clone()).await;
                info!("FakeDNS: Mapped {} -> {}", domain_name, new_ip);
                new_ip
            };

            let mut response = query.clone();
            response.set_message_type(MessageType::Response);
            response.set_response_code(ResponseCode::NoError);
            let record = Record::from_rdata(domain_name.clone(), 60, RData::A(hickory_proto::rr::rdata::A(fake_ip)));
            response.add_answer(record);

            Some(response)
        }

        pub async fn get_domain_by_ip(&self, ip: &IpAddr) -> Option<Name> {
            if let IpAddr::V4(ipv4) = ip {
                self.ip_to_domain.get(ipv4).await
            } else {
                None
            }
        }
    }
}

pub struct Tun<T, C> {
    client: Arc<Client<T, C>>,
    fakedns: Arc<FakeDns>,
}

impl<T, C> Clone for Tun<T, C> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            fakedns: self.fakedns.clone(),
        }
    }
}

impl<T, C> Tun<T, C>
where
    T: Initiator<Connection = C> + Send + Sync + 'static,
    C: Connection + Send + Sync + 'static,
{
    pub fn new(client: Arc<Client<T, C>>) -> Self {
        Self { client, fakedns: Arc::new(FakeDns::new(Ipv4Addr::new(198, 18, 0, 0))), }
    }

    /// 运行 TUN Endpoint 的主循环
    pub async fn run(
        &self,
        fd: i32,
        shutdown_signal: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        // 从文件描述符创建异步 TUN 设备
        let dev = unsafe { AsyncDevice::from_fd(fd)? };
        let framed = DeviceFramed::new(dev, BytesCodec::new());
        let (tun_sink, tun_stream) = framed.split::<bytes::Bytes>();

        // 初始化网络栈
        let (stack, tcp_listener, udp_socket) = NetStack::new(Config::default());
        let (stack_sink, stack_stream) = stack.split();

        let shutdown_token = CancellationToken::new();

        // 启动所有处理任务
        let processing_tasks = vec![
            tokio::spawn(Self::process_stack_to_tun(
                stack_stream,
                tun_sink,
                shutdown_token.clone(),
            )),
            tokio::spawn(Self::process_tun_to_stack(
                tun_stream,
                stack_sink,
                shutdown_token.clone(),
            )),
            tokio::spawn(
                self.clone()
                    .process_tcp_connections(tcp_listener, shutdown_token.clone()),
            ),
            tokio::spawn(
                self.clone()
                    .process_udp_packets(udp_socket, shutdown_token.clone()),
            ),
        ];

        // 等待外部的关闭信号
        shutdown_signal.await;
        info!("Shutdown signal received, terminating TUN tasks...");
        shutdown_token.cancel();

        // 等待所有任务结束
        for task in processing_tasks {
            if let Err(err) = task.await {
                error!("A processing task panicked or failed: {:?}", err);
            }
        }

        debug!("TUN stack has shut down completely.");
        Ok(())
    }

    /// 任务1: 从网络栈读取数据包并写入 TUN 设备
    async fn process_stack_to_tun(
        mut stack_stream: StackSplitStream,
        mut tun_sink: SplitSink<DeviceFramed<BytesCodec>, Bytes>,
        token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                pkt_result = stack_stream.next() => {
                    match pkt_result {
                        Some(Ok(pkt)) => {
                            if let Err(err) = tun_sink.send(pkt.into_bytes()).await {
                                error!("Failed to send packet to TUN: {}. Stopping task.", err);
                                break;
                            }
                        }
                        Some(Err(err)) => {
                            error!("Netstack read error: {}. Stopping task.", err);
                            break;
                        }
                        None => break, // 网络栈关闭
                    }
                }
            }
        }
        debug!("Stack-to-TUN task has finished.");
    }

    /// 任务2: 从 TUN 设备读取数据包并写入网络栈
    async fn process_tun_to_stack(
        mut tun_stream: SplitStream<DeviceFramed<BytesCodec>>,
        mut stack_sink: StackSplitSink,
        token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                pkt_result = tun_stream.next() => {
                    match pkt_result {
                        Some(Ok(pkt)) => {
                            if let Err(err) = stack_sink.send(Packet::new(pkt)).await {
                                error!("Failed to send packet to stack: {}. Stopping task.", err);
                                break;
                            }
                        }
                        Some(Err(err)) => {
                            error!("TUN stream read error: {}. Stopping task.", err);
                            break;
                        }
                        None => {
                            info!("TUN stream closed. Stopping TUN-to-stack task.");
                            break;
                        }
                    }
                }
            }
        }
        debug!("TUN-to-stack task has finished.");
    }

    /// 任务3: 处理来自网络栈的 TCP 连接
    async fn process_tcp_connections(
        self,
        mut tcp_listener: TcpListener,
        token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                stream_option = tcp_listener.next() => {
                    let stream = match stream_option {
                        Some(s) => s,
                        None => break, // 监听器关闭
                    };

                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = self_clone.handle_tcp_stream(stream).await {
                            // 忽略 BrokenPipe 和 ConnectionReset 错误，因为它们是正常关闭的常见情况
                            if err.kind() != io::ErrorKind::BrokenPipe && err.kind() != io::ErrorKind::ConnectionReset {
                                error!("Error handling TCP stream: {}", err);
                            }
                        }
                    });
                }
            }
        }
        debug!("TCP connection processing task has finished.");
    }

    /// 为每个 TCP 连接创建一个到远端的双向流
    async fn handle_tcp_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        let local_addr = stream.local_addr();
        let remote_addr = stream.remote_addr();

        let target_addr = if let Some(domain) = self.fakedns.get_domain_by_ip(&remote_addr.ip()).await {
            debug!("TCP New (FakeDNS): {} -> {} ({})", local_addr, remote_addr, domain);
            Address::from((domain.to_utf8(), remote_addr.port()))
        } else {
            debug!("TCP New: {} -> {}", local_addr, remote_addr);
            Address::from(remote_addr)
        };

        debug!(
            "TCP New: {} -> {} ({:?})",
            local_addr, remote_addr, target_addr
        );

        let mut remote_stream = self.client.open_bidirectional(target_addr.clone()).await?;

        let (up, down) =
            ombrac_transport::io::copy_bidirectional(&mut stream, &mut remote_stream).await?;

        info!(
            "TCP Close: {} -> {}. Sent: {}, Recv: {}",
            local_addr, remote_addr, up, down
        );

        Ok(())
    }

    /// 任务4: 处理来自网络栈的 UDP 数据包 (重构后的核心)
    async fn process_udp_packets(
        self, 
        udp_socket: UdpSocket, 
        token: CancellationToken
    ) {
        // 使用 Arc<Mutex<>> 来安全地在任务间共享 UdpSocket 的写入部分
        let (mut reader, writer) = udp_socket.split();
        let writer = Arc::new(Mutex::new(writer));

        // `sessions` 存储了每个内部源地址 (local_addr) 对应的处理任务的发送端
        let sessions: Arc<Mutex<DashMap<SocketAddr, mpsc::Sender<(Bytes, Address)>>>> =
            Arc::new(Mutex::new(DashMap::new()));

        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                packet_option = reader.recv() => {
                    let packet = match packet_option {
                        Some(p) => p,
                        None => break, // Socket 关闭
                    };


                    let local_addr = packet.local_addr;
                    let initial_remote_addr = packet.remote_addr;
                    let data: Bytes = packet.data.into_bytes();

                    // FAKE DNS
                    if packet.remote_addr.port() == 53 {
                        if let Some(response_message) = self.fakedns.handle_dns_query(&data).await {
                            match response_message.to_vec() {
                                Ok(response_bytes) => {
                                    let dns_response_packet = UdpPacket {
                                        data: Packet::new(response_bytes),
                                        local_addr: initial_remote_addr,
                                        remote_addr: local_addr,
                                    };
                                    let mut writer_guard = writer.lock().await;
                                    if let Err(e) = writer_guard.send(dns_response_packet).await {
                                        error!("Failed to send UDP packet back to TUN stack for {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to serialize DNS response: {}", e);
                                }
                            }
                            continue;
                        }
                    }

                    // let remote_addr = packet.remote_addr.into();
                    let remote_addr: Address = if let Some(domain) = self.fakedns.get_domain_by_ip(&initial_remote_addr.ip()).await {
                        debug!("UDP New (FakeDNS): {} -> {} ({})", local_addr, initial_remote_addr, domain);
                        Address::from((domain.to_utf8(), initial_remote_addr.port()))
                    } else {
                        debug!("UDP New: {} -> {}", local_addr, initial_remote_addr);
                        Address::from(initial_remote_addr)
                    };

                    let mut sessions_guard = sessions.lock().await;
                    let session_tx = sessions_guard.get(&local_addr);

                    match session_tx {
                        // 如果存在会话，直接发送数据
                        Some(tx) => {
                            if tx.send((data, remote_addr)).await.is_err() {
                                // 发送失败意味着处理任务已关闭，移除该会话
                                sessions_guard.remove(&local_addr);
                            }
                        }
                        // 如果不存在会话，创建一个新的
                        None => {
                            let (tx, rx) = mpsc::channel(128);
                            // 将初始数据包发送到新通道
                            if tx.send((data, remote_addr.clone())).await.is_err() {
                                // 如果连初始包都发送失败，就不创建任务了
                                continue;
                            }
                            sessions_guard.insert(local_addr, tx);

                            // 为这个新的 UDP 流启动一个专用的处理任务
                            tokio::spawn(self.clone().handle_udp_flow(
                                rx,
                                writer.clone(),
                                sessions.clone(),
                                local_addr,
                                initial_remote_addr,
                            ));
                        }
                    }
                }
            }
        }
        debug!("UDP packet processing task has finished.");
    }

    /// 为单个 UDP 流（由唯一的 local_addr 标识）处理双向数据转发
    async fn handle_udp_flow(
        self,
        mut rx: mpsc::Receiver<(Bytes, Address)>,
        writer: Arc<Mutex<SplitWrite>>,
        sessions: Arc<Mutex<DashMap<SocketAddr, mpsc::Sender<(Bytes, Address)>>>>,
        local_addr: SocketAddr,
        initial_remote_addr: SocketAddr,
    ) {
        debug!("UDP New Stream from {}", local_addr);
        let mut udp_session = self.client.open_associate();

        loop {
            tokio::select! {
                // 1. 从 `process_udp_packets` 接收发往远端的数据
                Some((data, dest_addr)) = rx.recv() => {
                    if let Err(e) = udp_session.send_to(data, dest_addr.clone()).await {
                        error!("Failed to send UDP packet from {} to {}: {}", local_addr, dest_addr, e);
                    }
                }

                // 2. 从远端接收数据，并发回网络栈
                Some((data, _from_addr)) = udp_session.recv_from() => {

                    // 注意，这里并不是错误，这个命名可能有歧义
                    // 使用初始的地址，而非收到的地址
                    let response_packet = UdpPacket {
                        data: Packet::new(data),
                        local_addr: initial_remote_addr,
                        remote_addr: local_addr,
                    };

                    let mut writer_guard = writer.lock().await;
                    if let Err(e) = writer_guard.send(response_packet).await {
                         error!("Failed to send UDP packet back to TUN stack for {}: {}", local_addr, e);
                    }
                }

                // 3. 超时检查
                _ = tokio::time::sleep(UDP_STREAM_TIMEOUT) => {
                    info!("UDP stream {} to {} timed out.", local_addr, initial_remote_addr);
                    break;
                }
            }
        }

        // 清理会话
        let mut sessions_guard = sessions.lock().await;
        sessions_guard.remove(&local_addr);
        debug!("UDP stream from {} closed and cleaned up.", local_addr);
    }
}
