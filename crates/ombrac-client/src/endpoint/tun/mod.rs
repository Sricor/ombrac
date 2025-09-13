mod debug;
mod device;
mod fakedns;
mod packet;
mod ring_buffer;
mod stack;
mod tcp_listener;
mod tcp_stream;
mod udp_socket;

pub use stack::{NetStack, Packet, StackSplitSink, StackSplitStream};
pub use tcp_stream::TcpStream;
pub use udp_socket::{UdpPacket, UdpSocket};

pub mod ombrac_client_tun {
    use crate::endpoint::tun::fakedns::FakeDns;

    use super::*;

    use std::{sync::Arc, time::Duration};

    use futures::{SinkExt, StreamExt};
    use ombrac::{prelude::Associate, Secret};
    use ombrac::client::Client;
    use ombrac_transport::Initiator;
    use tracing::{error, info, trace};
    use tun_rs::AsyncDevice;

    pub struct Tun<I: Initiator> {
        pub ombrac_client: Arc<Client<I>>,
        pub secret: Secret,
    }

    impl<I: Initiator> Tun<I> {
        pub async fn run(&self, fd: i32, shutdown_signal: impl Future<Output = ()>) {
            let dev = unsafe { AsyncDevice::from_fd(fd).unwrap() };

            let framed = tun_rs::async_framed::DeviceFramed::new(
                dev,
                tun_rs::async_framed::BytesCodec::new(),
            );

            let (stack, mut tcp_listener, udp_socket) = stack::NetStack::new();
            let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
            let (mut stack_sink, mut stack_stream) = stack.split();

            let mut futs: Vec<futures::future::BoxFuture<'static, std::io::Result<()>>> = vec![];

            let fakedns = Arc::new(FakeDns::new());
            let fakedns_for_cleanup = fakedns.clone();
            let dns_cleanup_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    fakedns_for_cleanup.cleanup_expired_entries();
                }
            });

            // dispatcher -> stack -> tun
            futs.push(Box::pin(async move {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                                error!("failed to send pkt to tun: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "tun stopped unexpectedly 0",
                ))
            }));

            // tun -> stack -> dispatcher
            futs.push(Box::pin(async move {
                while let Some(pkt) = tun_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = stack_sink.send(stack::Packet::new(pkt)).await {
                                error!("failed to send pkt to stack: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stream error: {}", e);
                            break;
                        }
                    }
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "tun stopped unexpectedly 1",
                ))
            }));

            let outbound_for_tcp = self.ombrac_client.clone();
            let fakedns_for_tcp = fakedns.clone();
            let secret = self.secret.clone();
            futs.push(Box::pin(async move {
                while let Some(stream) = tcp_listener.next().await {
                    let outbound = outbound_for_tcp.clone();
                    let fakedns_clone = fakedns_for_tcp.clone();

                    tokio::spawn(Self::handle_inbound_stream(
                        outbound,
                        secret,
                        stream,
                        fakedns_clone,
                    ));
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "tun TCP listener stopped unexpectedly",
                ))
            }));

            let outbound_for_udp = self.ombrac_client.clone();
            let fakedns_for_udp = fakedns.clone();
            futs.push(Box::pin(async move {
                let outbound = outbound_for_udp.clone();
                let fakedns_clone = fakedns_for_udp.clone();

                tokio::spawn(Self::handle_inbound_datagram(
                    outbound,
                    secret,
                    udp_socket,
                    fakedns_clone,
                ));

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "tun UDP listener stopped unexpectedly",
                ))
            }));

            tokio::select! {
                _ = shutdown_signal => {
                    info!("shutdown signal received, stopping tun");
                    dns_cleanup_handle.abort();
                }
                res = futures::future::select_all(futs) => {
                    // Handle the case where one of the futures completes first
                    if let Err(e) = res.0 {
                        error!("tun error: {}. stopped", e);
                        panic!("tun runner should not return error");
                    }
                }
            }
        }

        async fn handle_inbound_stream(
            outbound: Arc<Client<I>>,
            secret: Secret,
            mut stream: TcpStream,
            fakedns: Arc<FakeDns>,
        ) {
            use ombrac::address::{Address, Domain};

            let remote_addr = stream.remote_addr();
            let ip_to_lookup = remote_addr.ip();

            let target = if let Some(domain) = fakedns.lookup(&ip_to_lookup) {
                let port = remote_addr.port();
                Address::Domain(Domain::from_string(domain).unwrap(), port)
            } else {
                Address::from(remote_addr)
            };

            let mut remote_stream = match outbound.connect(target, secret).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to connect to remote target: {}", e);
                    return;
                }
            };

            if let Err(e) =
                ombrac::io::util::copy_bidirectional(&mut stream, &mut remote_stream).await
            {
                trace!("Bidirectional copy ended with error: {}", e);
            }
        }

        async fn handle_inbound_datagram(
            outbound: Arc<Client<I>>,
            secret: Secret,
            socket: UdpSocket,
            fakedns: Arc<FakeDns>,
        ) {
            use ombrac::address::{Address, Domain};

            let (mut r, mut w) = socket.split();
            while let Some(packet) = r.recv().await {
                let local_addr = packet.local_addr;
                let remote_addr = packet.remote_addr;

                if remote_addr.port() == 53 {
                    if let Some(fake_response_bytes) = fakedns.generate_fake_response(packet.data())
                    {
                        let response_packet = UdpPacket {
                            data: stack::Packet::new(fake_response_bytes),
                            local_addr: remote_addr,
                            remote_addr: local_addr,
                        };

                        if w.send(response_packet).await.is_err() {
                            error!("Failed to send fake DNS response back to TUN");
                        }
                    }

                    continue;
                }

                let target = if let Some(domain) = fakedns.lookup(&remote_addr.ip()) {
                    let port = remote_addr.port();
                    Address::Domain(Domain::from_string(domain).unwrap(), port)
                } else {
                    Address::from(remote_addr)
                };

                let a = outbound.associate().await.unwrap();
                a.send(Associate::with(secret, target, packet.data.into_bytes())).await.unwrap();
            }
        }
    }
}
