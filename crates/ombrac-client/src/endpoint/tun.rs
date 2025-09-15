use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use ombrac::Secret;
use ombrac::address::Domain;
use ombrac::client::Client;
use ombrac::prelude::Address;
use ombrac_macros::{error, info, warn};
use ombrac_netstack::*;
use ombrac_transport::Initiator;

use tokio_util::sync::CancellationToken;
use tun_rs::{
    AsyncDevice,
    async_framed::{BytesCodec, DeviceFramed},
};

pub struct Tun<I: Initiator> {
    pub ombrac_client: Arc<Client<I>>,
    pub fakedns: Arc<fakedns::FakeDns>,
    pub secret: Secret,
}

impl<I: Initiator> Tun<I> {
    /// Runs the main event loop for the TUN device, handling all network traffic.
    ///
    /// This function sets up the networking stack, spawns tasks to handle data flow
    /// between the TUN device and the network stack, and manages TCP and UDP traffic.
    /// It listens for a shutdown signal to terminate gracefully.
    pub async fn run(
        &self,
        fd: i32,
        shutdown_signal: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        // SAFETY: The caller must ensure that `fd` is a valid file descriptor
        // pointing to a TUN device, and that this function has exclusive access to it
        // for the lifetime of the device.
        let dev = unsafe { AsyncDevice::from_fd(fd)? };

        let framed = DeviceFramed::new(dev, BytesCodec::new());
        let (tun_sink, tun_stream) = framed.split::<bytes::Bytes>();

        let (stack, tcp_listener, udp_socket) = NetStack::new(Config::default());
        let (stack_sink, stack_stream) = stack.split();

        // Use a cancellation token to coordinate a graceful shutdown of all tasks.
        let shutdown_token = CancellationToken::new();

        // --- DNS Cleanup Task ---
        // This task periodically cleans up expired entries from the FakeDns cache.
        let fakedns_for_cleanup = self.fakedns.clone();
        let dns_cleanup_handle = {
            let token = shutdown_token.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            info!("DNS cleanup task is shutting down.");
                            break;
                        }
                        _ = interval.tick() => {
                            fakedns_for_cleanup.cleanup_expired_entries();
                        }
                    }
                }
            })
        };

        // --- Main Processing Tasks ---
        // Spawn each core processing loop as a separate background task.
        // This makes the system robust, as the failure of one task (e.g., TCP handler)
        // will not bring down the entire application.
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

        // Wait for the external shutdown signal.
        shutdown_signal.await;

        info!("Shutdown signal received. Shutting down all tasks...");
        shutdown_token.cancel();

        // Wait for all main tasks to complete.
        for task in processing_tasks {
            if let Err(e) = task.await {
                error!("A processing task panicked during shutdown: {:?}", e);
            }
        }

        // The DNS cleanup task is long-running and can be safely aborted.
        dns_cleanup_handle.abort();
        info!("TUN stack has shut down successfully.");

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
                            if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                                error!("Failed to send packet to TUN: {}. Stopping task.", e);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Netstack read error: {}. Stopping task.", e);
                            break;
                        }
                        None => {
                            info!("Netstack stream closed. Stopping stack-to-TUN task.");
                            break;
                        }
                    }
                }
            }
        }
        info!("Stack-to-TUN task has finished.");
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
                            if let Err(e) = stack_sink.send(Packet::new(pkt)).await {
                                error!("Failed to send packet to stack: {}. Stopping task.", e);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("TUN stream read error: {}. Stopping task.", e);
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
        info!("TUN-to-stack task has finished.");
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
                            info!("TCP listener has closed. Stopping TCP processing.");
                            break;
                        }
                    };

                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = self_clone.handle_inbound_stream(stream).await {
                            error!("Error handling TCP stream: {}", err);
                        }
                    });
                }
            }
        }
        info!("TCP connection processing task has finished.");
    }

    /// Task that processes all incoming UDP packets from the stack.
    async fn process_udp_packets(self, udp_socket: UdpSocket, token: CancellationToken) {
        self.handle_inbound_datagram(udp_socket, token).await;
        info!("UDP packet processing task has finished.");
    }

    /// Handles a single TCP stream by forwarding it through the ombrac client.
    async fn handle_inbound_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        let remote_addr = stream.remote_addr();

        // Check the FakeDNS cache to see if the destination IP corresponds to a domain name.
        let target_addr = if let Some(entry) = self.fakedns.lookup(&remote_addr.ip()) {
            let domain = entry.domain.clone();
            let port = remote_addr.port();
            Address::Domain(Domain::from_bytes(domain)?, port)
        } else {
            Address::from(remote_addr)
        };

        let mut remote_stream = self
            .ombrac_client
            .connect(target_addr.clone(), self.secret)
            .await?;

        // Copy data bidirectionally between the local stream and the remote stream.
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

    /// Handles all UDP datagrams from the local UDP socket.
    async fn handle_inbound_datagram(&self, socket: UdpSocket, token: CancellationToken) {
        let (mut tun_reader, mut tun_writer) = socket.split();

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

                    let local_addr = packet.local_addr;
                    let remote_addr = packet.remote_addr;
                    let data = packet.data.into_bytes();

                    // --- Handle Fake DNS for outgoing DNS queries ---
                    if remote_addr.port() == 53 {
                        if let Some(fake_response_bytes) = self.fakedns.generate_fake_response(&data) {
                            let response_packet = UdpPacket {
                                data: Packet::new(fake_response_bytes),
                                local_addr: remote_addr,
                                remote_addr: local_addr,
                            };

                            if tun_writer.send(response_packet).await.is_err() {
                                error!("Failed to send fake DNS response back to TUN");
                            }
                        }
                        continue;
                    }

                    // --- UDP Forwarding (Placeholder) ---
                    // FIX: The original code silently dropped all non-DNS UDP packets.
                    // This is now explicitly marked as not implemented. A full implementation
                    // requires a bidirectional relay mechanism, which depends on the `ombrac` client's API
                    // for handling connectionless datagrams and routing responses back.
                    warn!(
                        "UDP forwarding not implemented. Packet from {} to {} dropped.",
                        local_addr, remote_addr
                    );

                    // To implement this, need logic similar to this:
                    // 1. Look up the real destination from FakeDNS.
                    // 2. Use the ombrac client to send the packet.
                    // 3. Have a mechanism (likely in the client) to receive the response
                    //    and associate it back with the original `local_addr` to be sent
                    //    back into the TUN device via `tun_writer`.
                }
            }
        }
    }
}

impl<I: Initiator> Clone for Tun<I> {
    fn clone(&self) -> Self {
        Self {
            ombrac_client: self.ombrac_client.clone(),
            fakedns: self.fakedns.clone(),
            secret: self.secret,
        }
    }
}

pub mod fakedns {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use dashmap::DashMap;
    use dashmap::mapref::one::Ref;
    use tracing::debug;

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
