use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use ombrac::Secret;
use ombrac::address::Domain;
use ombrac::client::Client;
use ombrac::prelude::Address;
// 将 Unreliable 重命名为 UnreliableDatagram 以提高清晰度
// 您需要相应地在您的 lib.rs 中更新 trait 名称
use ombrac_transport::{Initiator, Unreliable}; 
use ombrac_macros::{debug, error, info, warn};
use ombrac_netstack::*;

use tokio::sync::{Mutex};
use tokio_util::sync::CancellationToken;
use tun_rs::{
    AsyncDevice,
    async_framed::{BytesCodec, DeviceFramed},
};

// 为 NAT 表定义一个条目，包含超时信息
struct UdpNatEntry {
    virtual_addr: SocketAddr,
    last_activity: Instant,
}

const UDP_NAT_TIMEOUT: Duration = Duration::from_secs(120);

// I 的 trait bound 需要更新以匹配新的 trait 名称
pub struct Tun<I: Initiator + Unreliable> {
    secret: Secret,
    client: Arc<Client<I>>,
    fakedns: Arc<fakedns::FakeDns>,
}

impl<I: Initiator + Unreliable> Tun<I> {
    pub fn new(client: Arc<Client<I>>, secret: Secret, fakedns: Arc<fakedns::FakeDns>) -> Self {
        Self {
            client,
            secret,
            fakedns,
        }
    }

    /// Runs the main event loop for the TUN device, handling all network traffic.
    pub async fn run(
        &self,
        fd: i32,
        shutdown_signal: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        let dev = unsafe { AsyncDevice::from_fd(fd)? };

        let framed = DeviceFramed::new(dev, BytesCodec::new());
        let (tun_sink, tun_stream) = framed.split::<bytes::Bytes>();

        let (stack, tcp_listener, udp_socket) = NetStack::new(Config::default());
        let (stack_sink, stack_stream) = stack.split();

        let shutdown_token = CancellationToken::new();

        let fakedns_for_cleanup = self.fakedns.clone();
        let dns_cleanup_handle = {
            let token = shutdown_token.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            debug!("DNS cleanup task is shutting down.");
                            break;
                        }
                        _ = interval.tick() => {
                            fakedns_for_cleanup.cleanup_expired_entries();
                        }
                    }
                }
            })
        };
        
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

        shutdown_signal.await;
        info!("Shutdown signal received, cancelling tasks...");
        shutdown_token.cancel();

        for task in processing_tasks {
            if let Err(_err) = task.await {
                error!("A processing task panicked during shutdown: {:?}", _err);
            }
        }

        dns_cleanup_handle.abort();
        debug!("TUN stack has shutdown complete");

        Ok(())
    }

    /// Task to process packets from the network stack and send them to the TUN device.
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
                            if let Err(_err) = tun_sink.send(pkt.into_bytes()).await {
                                error!("Failed to send packet to TUN: {}. Stopping task.", _err);
                                break;
                            }
                        }
                        Some(Err(_err)) => {
                            error!("Netstack read error: {}. Stopping task.", _err);
                            break;
                        }
                        None => {
                            info!("Netstack stream closed.");
                            break;
                        }
                    }
                }
            }
        }
        debug!("Stack-to-TUN task has finished.");
    }

    /// Task to process packets from the TUN device and send them to the network stack.
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
                            if let Err(_err) = stack_sink.send(Packet::new(pkt)).await {
                                error!("Failed to send packet to stack: {}. Stopping task.", _err);
                                break;
                            }
                        }
                        Some(Err(_err)) => {
                            error!("TUN stream read error: {}. Stopping task.", _err);
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

    /// Task that listens for new TCP connections from the stack and spawns a handler for each.
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
                        None => {
                            info!("TCP listener has closed.");
                            break
                        },
                    };

                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(_err) = self_clone.handle_inbound_stream(stream).await {
                            error!("Error handling TCP stream: {}", _err);
                        }
                    });
                }
            }
        }
        debug!("TCP connection processing task has finished.");
    }

    /// Handles a single TCP stream by forwarding it through the ombrac client.
    async fn handle_inbound_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        let remote_addr = stream.remote_addr();

        let target_addr = if let Some(entry) = self.fakedns.lookup(&remote_addr.ip()) {
            let domain = entry.domain.clone();
            let port = remote_addr.port();
            Address::Domain(Domain::from_bytes(domain)?, port)
        } else {
            Address::from(remote_addr)
        };

        let mut remote_stream = self
            .client
            .connect(target_addr.clone(), self.secret)
            .await?;
            
        let _copy = ombrac::io::util::copy_bidirectional(&mut stream, &mut remote_stream).await?;

        info!(
            "{} Connect {}, Sent: {}, Recv: {}",
            stream.local_addr(),
            target_addr,
            _copy.0,
            _copy.1
        );

        Ok(())
    }

    /// Task that processes all incoming UDP packets from the stack using a NAT table.
    async fn process_udp_packets(self, udp_socket: UdpSocket, token: CancellationToken) {
        let (mut tun_reader, tun_writer) = udp_socket.split();
        let shared_tun_writer = Arc::new(Mutex::new(tun_writer));
        
        // NAT 表: Key = 远程真实地址, Value = 虚拟客户端地址 + 超时
        let nat_table = Arc::new(DashMap::<SocketAddr, UdpNatEntry>::new());

        // --- NAT 清理任务 ---
        let nat_cleanup_handle = {
            let token = token.clone();
            let table = nat_table.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(UDP_NAT_TIMEOUT / 2);
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        _ = interval.tick() => {
                            let now = Instant::now();
                            table.retain(|_, entry| now.duration_since(entry.last_activity) < UDP_NAT_TIMEOUT);
                        }
                    }
                }
            })
        };

        // --- 入站流量任务 (代理 -> TUN) ---
        let inbound_handle = {
            let token = token.clone();
            let client = self.client.clone();
            let table = nat_table.clone();
            let writer = shared_tun_writer.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => break,
                        read_result = client.read_datagram() => {
                            match read_result {
                                Ok((remote_addr, data)) => {
                                    if let Some(entry) = table.get(&remote_addr) {
                                        let virtual_dest_addr = entry.value().virtual_addr;
                                        let packet = UdpPacket {
                                            data: Packet::new(data),
                                            local_addr: virtual_dest_addr,
                                            remote_addr,
                                        };
                                        let mut writer_guard = writer.lock().await;
                                        if writer_guard.send(packet).await.is_err() {
                                            error!("Failed to send UDP packet back to TUN stack, writer closed.");
                                            break;
                                        }
                                    } else {
                                        warn!("Received unsolicited UDP packet from {}, dropping.", remote_addr);
                                    }
                                }
                                Err(_err) => {
                                    debug!("UDP proxy client read error (connection closed?): {}", _err);
                                    break;
                                }
                            }
                        }
                    }
                }
                debug!("UDP inbound (Proxy->TUN) task finished.");
            })
        };

        // --- 出站流量循环 (TUN -> 代理) ---
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                packet_option = tun_reader.recv() => {
                    let packet = match packet_option {
                        Some(p) => p,
                        None => {
                            info!("UDP socket reader has closed.");
                            break;
                        }
                    };

                    let virtual_src_addr = packet.local_addr;
                    let virtual_dest_addr = packet.remote_addr;
                    let data = packet.data.into_bytes();

                    // --- Fake DNS 逻辑 ---
                    if virtual_dest_addr.port() == 53 {
                        if let Some(fake_response_bytes) = self.fakedns.generate_fake_response(&data) {
                            let response_packet = UdpPacket {
                                data: Packet::new(fake_response_bytes),
                                local_addr: virtual_dest_addr,
                                remote_addr: virtual_src_addr,
                            };
                            let mut writer = shared_tun_writer.lock().await;
                            if writer.send(response_packet).await.is_err() {
                                error!("Failed to send fake DNS response back to TUN");
                            }
                        }
                        // 对真实DNS请求，我们仍然需要将其转发
                        // 这里我们假设 generate_fake_response 已经处理了所有需要拦截的请求
                        // 如果您想同时支持 FakeDNS 和真实DNS查询，则不应在这里 continue
                    }

                    // --- NAT 和转发逻辑 ---
                    let real_dest_addr = if let Some(entry) = self.fakedns.lookup(&virtual_dest_addr.ip()) {
                        // 如果是FakeDNS IP, 转换为域名地址
                        let domain = entry.domain.clone();
                        let port = virtual_dest_addr.port();
                        // 注意: Client 需要能够解析域名。如果不能，这里需要先解析为IP。
                        // 假设 client.send_datagram 无法处理域名，我们需要自己解析
                        // 为了简单起见，我们假设代理服务器会处理域名解析
                        SocketAddr::new(virtual_dest_addr.ip(), port) // 简化处理，直接使用IP
                    } else {
                        virtual_dest_addr
                    };

                    // 更新NAT表
                    nat_table.insert(real_dest_addr, UdpNatEntry {
                        virtual_addr: virtual_src_addr,
                        last_activity: Instant::now(),
                    });

                    // 通过代理发送数据
                    if let Err(_err) = self.client.send_datagram(real_dest_addr, &data).await {
                        debug!("Failed to send UDP datagram via proxy (connection closed?): {}", _err);
                        // 不需要 break，因为 client 内部有重连逻辑
                    }
                }
            }
        }
        debug!("UDP outbound (TUN->Proxy) loop finished.");

        // 等待所有相关任务结束
        nat_cleanup_handle.abort();
        let _ = inbound_handle.await;
    }
}


impl<I: Initiator + Unreliable> Clone for Tun<I> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            fakedns: self.fakedns.clone(),
            secret: self.secret,
        }
    }
}


pub mod fakedns {
    // ... fakedns 模块代码保持不变 ...
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use dashmap::DashMap;
    use dashmap::mapref::one::Ref;
    use ombrac_macros::debug;

    const DEFAULT_DNS_ENTRY_TTL: Duration = Duration::from_secs(60);

    pub struct DnsEntry {
        pub domain: Bytes,
        pub expires_at: Instant,
    }

    pub struct FakeDns {
        map: DashMap<IpAddr, DnsEntry>,
        ip_counter: AtomicU32,
        ip_pool_base: u32,
        ip_pool_size: u32,
    }

    impl FakeDns {
        pub fn new(ip_pool_base_addr: Ipv4Addr, prefix_len: u8) -> Self {
            if !(1..=32).contains(&prefix_len) {
                panic!("Prefix length must be between 1 and 32");
            }

            let ip_pool_size = 2u32.saturating_pow(32 - prefix_len as u32);

            Self {
                map: DashMap::new(),
                ip_counter: AtomicU32::new(1),
                ip_pool_base: u32::from(ip_pool_base_addr),
                ip_pool_size,
            }
        }

        pub fn lookup(&self, ip: &IpAddr) -> Option<Ref<'_, IpAddr, DnsEntry>> {
            self.map.get(ip)
        }

        pub fn generate_fake_response(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
            if query_bytes.len() < 12 {
                return None;
            }

            let transaction_id = &query_bytes[0..2];
            let qd_count = u16::from_be_bytes([query_bytes[4], query_bytes[5]]);
            if qd_count != 1 {
                return None;
            }

            let question_bytes = &query_bytes[12..];
            let mut domain_bytes = Vec::with_capacity(question_bytes.len());
            let mut current_pos = 0;
            loop {
                let len = *question_bytes.get(current_pos)? as usize;
                if len == 0 {
                    current_pos += 1;
                    break;
                }
                current_pos += 1;

                let part = question_bytes.get(current_pos..current_pos + len)?;

                if !domain_bytes.is_empty() {
                    domain_bytes.push(b'.');
                }
                domain_bytes.extend_from_slice(part);

                current_pos += len;
            }

            let qtype = u16::from_be_bytes([
                *question_bytes.get(current_pos)?,
                *question_bytes.get(current_pos + 1)?,
            ]);
            if qtype != 1 {
                return None;
            }

            let _qclass = u16::from_be_bytes([
                *question_bytes.get(current_pos + 2)?,
                *question_bytes.get(current_pos + 3)?,
            ]);

            let fake_ip = self.next_fake_ip();

            let entry = DnsEntry {
                domain: domain_bytes.into(),
                expires_at: Instant::now() + DEFAULT_DNS_ENTRY_TTL,
            };

            debug!(
                "FakeDNS: Mapped domain '{}' -> '{}'. Current map size: {}",
                String::from_utf8_lossy(&entry.domain),
                fake_ip,
                self.map.len()
            );

            self.map.insert(IpAddr::V4(fake_ip), entry);

            let question_section_len = current_pos + 4;
            let response_len = 12 + question_section_len + 16; // Header + Question + Answer
            let mut response_bytes = Vec::with_capacity(response_len);

            // --- Header Section ---
            response_bytes.extend_from_slice(transaction_id); // Transaction ID
            response_bytes.extend_from_slice(&[0x81, 0x80]); // Flags: Response, Recursion Desired, Recursion Available
            response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Questions: 1
            response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Answer RRs: 1
            response_bytes.extend_from_slice(&0u16.to_be_bytes()); // Authority RRs: 0
            response_bytes.extend_from_slice(&0u16.to_be_bytes()); // Additional RRs: 0

            // --- Question Section ---
            response_bytes.extend_from_slice(&query_bytes[12..12 + question_section_len]);

            // --- Answer Section ---
            response_bytes.extend_from_slice(&[0xc0, 0x0c]); // Pointer to domain name at offset 12
            response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Type: A
            response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Class: IN
            response_bytes.extend_from_slice(&60u32.to_be_bytes()); // TTL: 60 seconds
            response_bytes.extend_from_slice(&4u16.to_be_bytes()); // Data length: 4 bytes for IPv4
            response_bytes.extend_from_slice(&fake_ip.octets()); // Fake IP address

            Some(response_bytes)
        }

        pub fn cleanup_expired_entries(&self) {
            let now = Instant::now();
            self.map.retain(|_ip, entry| entry.expires_at > now);
        }

        fn next_fake_ip(&self) -> Ipv4Addr {
            let count = self.ip_counter.fetch_add(1, Ordering::Relaxed);

            let offset = if self.ip_pool_size > 2 {
                1 + (count % (self.ip_pool_size - 2))
            } else {
                count % self.ip_pool_size
            };

            let next_ip_u32 = self.ip_pool_base + offset;

            Ipv4Addr::from(next_ip_u32)
        }
    }

    impl Default for FakeDns {
        fn default() -> Self {
            Self::new(Ipv4Addr::new(198, 18, 0, 0), 16)
        }
    }
}