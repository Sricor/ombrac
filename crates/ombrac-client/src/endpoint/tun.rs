use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{
    stream::{SplitSink, SplitStream},
    {SinkExt, StreamExt},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tun_rs::{
    AsyncDevice,
    async_framed::{BytesCodec, DeviceFramed},
};

use ombrac::protocol::Address;
use ombrac_macros::{debug, error, info, warn};
use ombrac_netstack::*;
use ombrac_transport::{Connection, Initiator};

use crate::client::Client;

type NatEntry = (SocketAddr, Instant);

pub struct Tun<T, C> {
    client: Arc<Client<T, C>>,
}

impl<T, C> Tun<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    pub fn new(client: Arc<Client<T, C>>) -> Self {
        Self { client }
    }

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

        let udp_nat_table: Arc<DashMap<SocketAddr, NatEntry>> = Arc::new(DashMap::new());
        let nat_cleanup_handle = {
            let table = udp_nat_table.clone();
            let token = shutdown_token.clone();
            tokio::spawn(async move {
                const UDP_NAT_TIMEOUT: Duration = Duration::from_secs(60);
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                debug!("UDP NAT cleanup task started.");
                loop {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => {
                            debug!("UDP NAT cleanup task is shutting down.");
                            break;
                        }
                        _ = interval.tick() => {
                            let before = table.len();
                            table.retain(|_, (_, ts)| ts.elapsed() < UDP_NAT_TIMEOUT);
                            let after = table.len();
                            if before > after {
                                debug!("Cleaned up {} expired UDP NAT entries.", before - after);
                            }
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
            tokio::spawn(self.clone().process_udp_packets(
                udp_socket,
                udp_nat_table,
                shutdown_token.clone(),
            )),
        ];

        shutdown_signal.await;
        info!("Shutdown signal received, terminating TUN tasks...");
        shutdown_token.cancel();

        for task in processing_tasks {
            if let Err(err) = task.await {
                error!("A processing task panicked or failed: {:?}", err);
            }
        }

        nat_cleanup_handle.abort();
        debug!("TUN stack has shut down completely.");

        Ok(())
    }

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
                        None => break,
                    }
                }
            }
        }
        debug!("Stack-to-TUN task has finished.");
    }

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
                        None => break
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
        debug!("TCP connection processing task has finished.");
    }

    async fn process_udp_packets(
        self,
        udp_socket: UdpSocket,
        nat_table: Arc<DashMap<Address, NatEntry>>,
        token: CancellationToken,
    ) {
        self.handle_inbound_datagram(udp_socket, nat_table, token)
            .await;
        debug!("UDP packet processing task has finished.");
    }

    async fn handle_inbound_stream(&self, mut stream: TcpStream) -> io::Result<()> {
        let remote_addr = stream.remote_addr();
        let target_addr = Address::from(remote_addr);

        let mut remote_stream = self.client.open_bidirectional(target_addr.clone()).await?;

        let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await?;

        info!(
            "TCP Close: {} <-> {:?}. Sent: {}, Recv: {}",
            stream.local_addr(),
            target_addr,
            up,
            down
        );

        Ok(())
    }

    async fn handle_inbound_datagram(
        &self,
        socket: UdpSocket,
        nat_table: Arc<DashMap<Address, NatEntry>>,
        token: CancellationToken,
    ) {
        let (mut tun_reader, mut tun_writer) = socket.split();

        let (proxy_to_tun_sender, mut proxy_to_tun_receiver) = mpsc::channel::<UdpPacket>(1024);

        let client_clone = self.client.clone();
        let nat_table_clone = nat_table.clone();
        let token_clone = token.clone();
        let tun_to_proxy = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token_clone.cancelled() => break,
                    packet_option = tun_reader.recv() => {
                        let packet = match packet_option {
                            Some(p) => p,
                            None => break,
                        };

                        nat_table_clone.insert(packet.remote_addr.into(), (packet.local_addr, Instant::now()));

                        if let Err(e) = client_clone.send_datagram(packet.remote_addr, &packet.data.into_bytes()).await {
                            error!("Failed to send UDP datagram via proxy for {}: {}", packet.remote_addr, e);
                        }
                    }
                }
            }
            debug!("UDP TUN-to-Proxy task has finished.");
        });

        let token_clone2 = token.clone();
        let self_clone = self.clone();
        let proxy_to_channel = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token_clone2.cancelled() => break,
                    datagram_result = self_clone.client.read_datagram() => {
                        match datagram_result {
                            Ok((source_addr, data)) => {
                                if let Some(mut entry) = nat_table.get_mut(&source_addr) {
                                    let dest_addr = entry.value().0;
                                    let response_packet = UdpPacket {
                                        data: Packet::new(data),
                                        local_addr: source_addr,
                                        remote_addr: dest_addr,
                                    };

                                    // 非阻塞地将包发送到 channel，锁的范围极小
                                    if let Err(_) = proxy_to_tun_sender.send(response_packet).await {
                                        error!("Proxy-to-TUN channel closed. Stopping task.");
                                        break;
                                    }
                                    entry.value_mut().1 = Instant::now();
                                } else {
                                    warn!("Received UDP packet from unknown source {}, no NAT entry found. Dropping.", source_addr);
                                }
                            }
                            Err(e) => {
                                error!("Failed to read UDP datagram from proxy: {}. Stopping task.", e);
                                break;
                            }
                        }
                    }
                }
            }
            debug!("UDP Proxy-to-Channel task has finished.");
        });

        let token_clone3 = token.clone();
        let channel_to_tun = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token_clone3.cancelled() => break,
                    Some(packet) = proxy_to_tun_receiver.recv() => {
                        if let Err(e) = tun_writer.send(packet).await {
                            error!("Failed to send UDP packet to TUN stack: {}", e);
                        }
                    }
                    else => break, // Channel closed
                }
            }
            debug!("UDP Channel-to-TUN writer task has finished.");
        });

        tokio::select! {
            _ = tun_to_proxy => {},
            _ = proxy_to_channel => {},
            _ = channel_to_tun => {},
            _ = token.cancelled() => {},
        }
    }
}

impl<T, C> Clone for Tun<T, C> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}
