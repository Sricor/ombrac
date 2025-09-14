mod debug;
mod device;
pub mod fakedns;
mod packet;
mod ring_buffer;
mod stack;
mod tcp_listener;
mod tcp_stream;
mod udp_socket;

pub use stack::{NetStack, Packet, StackSplitSink, StackSplitStream};
pub use tcp_stream::TcpStream;
pub use udp_socket::{UdpPacket, UdpSocket};

use ombrac::address::{Address, Domain};

pub mod ombrac_client_tun {
    use crate::endpoint::tun::fakedns::FakeDns;

    use super::*;

    use std::future::Future;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use futures::stream::{SplitSink, SplitStream};
    use futures::{SinkExt, StreamExt};
    use ombrac::Secret;
    use ombrac::client::Client;
    use ombrac_macros::{error, info, warn};
    use ombrac_transport::Initiator;

    use tokio_util::sync::CancellationToken;
    use tun_rs::{
        AsyncDevice,
        async_framed::{BytesCodec, DeviceFramed},
    };

    pub struct Tun<I: Initiator> {
        pub ombrac_client: Arc<Client<I>>,
        pub fakedns: Arc<FakeDns>,
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

            let (stack, tcp_listener, udp_socket) = NetStack::new();
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
                                if let Err(e) = stack_sink.send(stack::Packet::new(pkt)).await {
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
            mut tcp_listener: super::tcp_listener::TcpListener,
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
            let _copy =
                ombrac::io::util::copy_bidirectional(&mut stream, &mut remote_stream).await?;

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
                                    data: stack::Packet::new(fake_response_bytes),
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
}
