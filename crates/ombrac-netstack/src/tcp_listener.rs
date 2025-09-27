use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::task::AtomicWaker;
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer};
use smoltcp::{
    iface::{Interface, SocketSet},
    socket::tcp,
    wire::{IpProtocol, TcpPacket},
};
use tokio::sync::mpsc;

use crate::error;
use crate::{
    Config, Packet,
    buffer::BufferPool,
    device::NetstackDevice,
    packet::IpPacket,
    stack::IfaceEvent,
    tcp_stream::{RbConsumer, RbProducer, SharedState, TcpStream},
};

pub(crate) struct SocketIOHandle {
    recv_buffer_prod: RbProducer,
    send_buffer_cons: RbConsumer,
    shared_state: Arc<SharedState>,
}

pub struct TcpListener {
    socket_stream: mpsc::Receiver<TcpStream>,
    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

impl TcpListener {
    pub fn new(
        config: Config,
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        buffer_pool: Arc<BufferPool>,
    ) -> Self {
        let (iface_notifier, iface_notifier_rx) = mpsc::channel(config.channel_size);
        let mut device =
            NetstackDevice::new(outbound, iface_notifier.clone(), buffer_pool, &config);
        let mut iface = Self::create_interface(&config, &mut device);

        let (socket_stream_emitter, socket_stream) =
            mpsc::channel::<TcpStream>(config.channel_size);
        let socket_stream_waker = Arc::new(AtomicWaker::new());

        let waker = socket_stream_waker.clone();
        let task_handle = tokio::spawn(async move {
            let _ = tokio::select! {
                rv = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter, waker, &config) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx) => rv,
            };
        });

        TcpListener {
            socket_stream,
            task_handle,
        }
    }

    fn create_interface(config: &Config, device: &mut NetstackDevice) -> Interface {
        let mut iface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface =
            smoltcp::iface::Interface::new(iface_config, device, smoltcp::time::Instant::now());

        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                config.ipv4_addr.into(),
                config.ipv4_prefix_len,
            ));
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                config.ipv6_addr.into(),
                config.ipv6_prefix_len,
            ));
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(config.ipv4_addr)
            .expect("Failed to add default IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(config.ipv6_addr)
            .expect("Failed to add default IPv6 route");

        iface
    }

    async fn process_inbound_frame(
        config: &Config,
        frame: Packet,
        device_injector: &mpsc::Sender<Packet>,
        iface_notifier: &mpsc::Sender<IfaceEvent<'static>>,
        tcp_stream_emitter: &mpsc::Sender<TcpStream>,
        tcp_stream_waker: &Arc<AtomicWaker>,
    ) -> std::io::Result<()> {
        let packet = IpPacket::new_checked(frame.data()).map_err(std::io::Error::other)?;

        if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
            if device_injector.try_send(frame).is_ok() {
                let _ = iface_notifier.try_send(IfaceEvent::Icmp);
            }
            return Ok(());
        }

        let payload = packet.payload();
        let tcp_packet = TcpPacket::new_checked(payload).map_err(std::io::Error::other)?;

        if tcp_packet.syn() && !tcp_packet.ack() {
            let src_addr = SocketAddr::new(packet.src_addr(), tcp_packet.src_port());
            let dst_addr = SocketAddr::new(packet.dst_addr(), tcp_packet.dst_port());

            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; config.tcp_recv_buffer_size]),
                tcp::SocketBuffer::new(vec![0u8; config.tcp_send_buffer_size]),
            );

            socket.set_keep_alive(Some(config.tcp_keep_alive.into()));
            socket.set_timeout(Some(config.tcp_timeout.into()));
            socket.set_ack_delay(Some(config.tcp_ack_delay.into()));
            socket.set_nagle_enabled(false);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);

            if socket.listen(dst_addr).is_ok() {
                let recv_rb = Arc::new(HeapRb::<u8>::new(config.tcp_recv_buffer_size));
                let (recv_prod, recv_cons) = (
                    ringbuf::Prod::new(recv_rb.clone()),
                    ringbuf::Cons::new(recv_rb),
                );

                let send_rb = Arc::new(HeapRb::<u8>::new(config.tcp_send_buffer_size));
                let (send_prod, send_cons) = (
                    ringbuf::Prod::new(send_rb.clone()),
                    ringbuf::Cons::new(send_rb),
                );

                let shared_state = Arc::new(SharedState::new());
                let stream = TcpStream {
                    local_addr: src_addr,
                    remote_addr: dst_addr,
                    recv_buffer_cons: recv_cons,
                    send_buffer_prod: send_prod,
                    shared_state: shared_state.clone(),
                    stack_notifier: iface_notifier.clone(),
                };

                let io_handle = SocketIOHandle {
                    recv_buffer_prod: recv_prod,
                    send_buffer_cons: send_cons,
                    shared_state,
                };

                if tcp_stream_emitter.try_send(stream).is_ok()
                    && iface_notifier
                        .send(IfaceEvent::TcpStream(Box::new((socket, io_handle))))
                        .await
                        .is_ok()
                {
                    tcp_stream_waker.wake();
                }
            }
        }

        device_injector
            .try_send(frame)
            .map_err(|_| std::io::Error::other("Failed to inject packet to device"))?;

        Ok(())
    }

    async fn poll_packets(
        mut inbound: mpsc::Receiver<Packet>,
        device_injector: mpsc::Sender<Packet>,
        iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::Sender<TcpStream>,
        tcp_stream_waker: Arc<AtomicWaker>,
        config: &Config,
    ) -> std::io::Result<()> {
        let mut packet_buf = Vec::with_capacity(config.packet_batch_size);

        loop {
            let n = inbound
                .recv_many(&mut packet_buf, config.packet_batch_size)
                .await;
            if n == 0 {
                break;
            }

            for frame in packet_buf.drain(..) {
                if let Err(_err) = Self::process_inbound_frame(
                    config,
                    frame,
                    &device_injector,
                    &iface_notifier,
                    &tcp_stream_emitter,
                    &tcp_stream_waker,
                )
                .await
                {
                    error!("{_err}");
                }
            }

            if let Err(_err) = iface_notifier.try_send(IfaceEvent::DeviceReady) {
                error!("{_err}");
            }
        }

        Ok(())
    }

    fn handle_socket_io(socket: &mut tcp::Socket, socket_control: &mut SocketIOHandle) {
        let mut notify_read = false;
        if socket.can_recv() {
            match socket.recv(|buffer| {
                let n = socket_control.recv_buffer_prod.push_slice(buffer);
                (n, buffer.len())
            }) {
                Ok(n) => {
                    if n > 0 {
                        notify_read = true;
                    }
                }
                Err(_) => {
                    socket_control.shared_state.read_closed.store(true, std::sync::atomic::Ordering::Release);
                    notify_read = true;
                }
            }
        }

        if !socket.can_recv() && socket.state() != tcp::State::Listen {
            socket_control.shared_state.read_closed.store(true, std::sync::atomic::Ordering::Release);
            notify_read = true;
        }

        if notify_read {
            socket_control.shared_state.recv_waker.wake();
        }

        let mut notify_write = false;
        while socket.can_send() && !socket_control.send_buffer_cons.is_empty() {
            match socket.send(|buffer| {
                (
                    socket_control.send_buffer_cons.pop_slice(buffer),
                    buffer.len(),
                )
            }) {
                Ok(n) if n > 0 => notify_write = true,
                _ => break,
            }
        }
        if notify_write {
            socket_control.shared_state.send_waker.wake();
        }
    }

    fn prune_sockets(
        sockets: &mut SocketSet,
        socket_maps: &mut HashMap<smoltcp::iface::SocketHandle, SocketIOHandle>,
    ) {
        socket_maps.retain(|handle, socket_control| {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);

            if socket_control
                .shared_state
                .socket_dropped
                .load(std::sync::atomic::Ordering::Acquire)
            {
                socket.close();
            }

            if !socket.is_active() {
                sockets.remove(*handle);
                return false;
            }

            true
        });
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::Receiver<IfaceEvent<'_>>,
    ) -> std::io::Result<()> {
        const HOUSEKEEPING_INTERVAL: Duration = Duration::from_millis(100);

        let mut sockets = SocketSet::new(vec![]);
        let mut socket_maps: HashMap<smoltcp::iface::SocketHandle, SocketIOHandle> = HashMap::new();

        let mut housekeeping_timer = tokio::time::interval(HOUSEKEEPING_INTERVAL);

        loop {
            let now = smoltcp::time::Instant::now();
            let smoltcp_delay = iface
                .poll_delay(now, &sockets)
                .map(|d| d.into())
                .unwrap_or(HOUSEKEEPING_INTERVAL);

            tokio::select! {
                biased;
                Some(event) = notifier_rx.recv() => {
                    if let IfaceEvent::TcpStream(stream) = event {
                        let (socket, handle) = *stream;
                        let socket_handle = sockets.add(socket);
                        socket_maps.insert(socket_handle, handle);
                    }
                }
                _ = tokio::time::sleep(smoltcp_delay) => {},
                _ = housekeeping_timer.tick() => {},
            }

            let now = smoltcp::time::Instant::now();
            iface.poll(now, device, &mut sockets);

            for (socket_handle, socket_control) in socket_maps.iter_mut() {
                let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);
                Self::handle_socket_io(socket, socket_control);
            }

            Self::prune_sockets(&mut sockets, &mut socket_maps);
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.socket_stream.poll_recv(cx)
    }
}
