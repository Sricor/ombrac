use futures::task::AtomicWaker;
use smoltcp::{
    iface::{Interface, SocketSet},
    socket::tcp,
    wire::{IpProtocol, TcpPacket},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::mpsc;

use crate::{
    Config, Packet,
    buffer::{BufferPool, LockFreeRingBuffer},
    device::NetstackDevice,
    error,
    packet::IpPacket,
    stack::IfaceEvent,
    tcp_stream::TcpStream,
};

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_waker: AtomicWaker,
    pub(crate) socket_dropped: AtomicBool,
}

impl TcpStreamHandle {
    pub fn new(recv_buffer_size: usize, send_buffer_size: usize) -> Self {
        Self {
            recv_waker: AtomicWaker::new(),
            send_waker: AtomicWaker::new(),
            recv_buffer: LockFreeRingBuffer::new(recv_buffer_size),
            send_buffer: LockFreeRingBuffer::new(send_buffer_size),
            socket_dropped: AtomicBool::new(false),
        }
    }
}

pub struct TcpListener {
    socket_stream: mpsc::Receiver<TcpStream>,
    socket_stream_waker: Arc<AtomicWaker>,
    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

impl TcpListener {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        buffer_pool: Arc<BufferPool>,
        config: Config,
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
            socket_stream_waker,
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
        frame: Packet,
        device_injector: &mpsc::Sender<Packet>,
        iface_notifier: &mpsc::Sender<IfaceEvent<'static>>,
        tcp_stream_emitter: &mpsc::Sender<TcpStream>,
        tcp_stream_waker: &Arc<AtomicWaker>,
        config: &Config,
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

            socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                if cfg!(target_os = "linux") { 7200 } else { 60 },
            )));
            socket.set_ack_delay(Some(Duration::from_millis(10).into()));
            socket.set_nagle_enabled(false);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);

            if socket.listen(dst_addr).is_ok() {
                let handle = Arc::new(TcpStreamHandle::new(
                    config.tcp_recv_buffer_size,
                    config.tcp_send_buffer_size,
                ));

                let stream = TcpStream {
                    local_addr: src_addr,
                    remote_addr: dst_addr,
                    handle: handle.clone(),
                    stack_notifier: iface_notifier.clone(),
                };

                if tcp_stream_emitter.try_send(stream).is_ok()
                    && iface_notifier
                        .send(IfaceEvent::TcpStream(Box::new((socket, handle))))
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
        let mut packet_buf = Vec::with_capacity(32);

        loop {
            let n = inbound.recv_many(&mut packet_buf, 32).await;
            if n == 0 {
                break;
            }

            for frame in packet_buf.drain(..) {
                if let Err(_err) = Self::process_inbound_frame(
                    frame,
                    &device_injector,
                    &iface_notifier,
                    &tcp_stream_emitter,
                    &tcp_stream_waker,
                    config,
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

    fn handle_socket_io(socket: &mut tcp::Socket, socket_control: &Arc<TcpStreamHandle>) {
        let recv_buf = &socket_control.recv_buffer;
        let mut notify_read = false;
        while socket.can_recv() && !recv_buf.is_full() {
            if let Ok(n) = socket.recv(|buffer| (recv_buf.enqueue_slice(buffer), buffer.len())) {
                if n > 0 {
                    notify_read = true;
                }
            } else {
                break;
            }
        }
        if notify_read {
            socket_control.recv_waker.wake();
        }

        let send_buf = &socket_control.send_buffer;
        let mut notify_write = false;
        while socket.can_send() && !send_buf.is_empty() {
            if let Ok(n) = socket.send(|buffer| (send_buf.dequeue_slice(buffer), buffer.len())) {
                if n > 0 {
                    notify_write = true;
                }
            } else {
                break;
            }
        }
        if notify_write {
            socket_control.send_waker.wake();
        }
    }

    fn prune_sockets(
        sockets: &mut SocketSet,
        socket_maps: &mut HashMap<smoltcp::iface::SocketHandle, Arc<TcpStreamHandle>>,
    ) {
        socket_maps.retain(|handle, socket_control| {
            if socket_control
                .socket_dropped
                .load(std::sync::atomic::Ordering::Acquire)
            {
                sockets.remove(*handle);
                return false;
            }
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
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
        let mut sockets = SocketSet::new(vec![]);
        let mut socket_maps: HashMap<smoltcp::iface::SocketHandle, Arc<TcpStreamHandle>> =
            HashMap::new();

        loop {
            let now = smoltcp::time::Instant::now();
            let delay = iface
                .poll_delay(now, &sockets)
                .unwrap_or(smoltcp::time::Duration::ZERO)
                .into();

            tokio::select! {
                biased;
                Some(event) = notifier_rx.recv() => {
                    if let IfaceEvent::TcpStream(stream) = event {
                        let socket_handle = sockets.add(stream.0);
                        socket_maps.insert(socket_handle, stream.1);
                    }
                }
                _ = tokio::time::sleep(delay) => {}
            }

            let now = smoltcp::time::Instant::now();
            iface.poll(now, device, &mut sockets);

            for (socket_handle, socket_control) in socket_maps.iter() {
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
        match self.socket_stream.try_recv() {
            Ok(stream) => std::task::Poll::Ready(Some(stream)),
            Err(mpsc::error::TryRecvError::Empty) => {
                self.socket_stream_waker.register(cx.waker());
                std::task::Poll::Pending
            }
            Err(mpsc::error::TryRecvError::Disconnected) => std::task::Poll::Ready(None),
        }
    }
}
