use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use smoltcp::wire::IpProtocol;
use tokio::sync::mpsc;

use crate::debug;
use crate::{
    Config, UdpSocket,
    buffer::BufferPool,
    packet::IpPacket,
    tcp_listener::{TcpListener, TcpStreamHandle},
};

pub(crate) enum IfaceEvent<'a> {
    Icmp,
    TcpStream(Box<(smoltcp::socket::tcp::Socket<'a>, Arc<TcpStreamHandle>)>),
    TcpSocketReady,
    TcpSocketClosed,
    DeviceReady,
}

pub struct NetStack {
    udp_inbound: mpsc::Sender<Packet>,
    tcp_inbound: mpsc::Sender<Packet>,
    packet_outbound: mpsc::Receiver<Packet>,
}

pub struct Packet {
    data: Bytes,
}

impl Packet {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet { data: data.into() }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl<T> From<T> for Packet
where
    T: Into<Bytes>,
{
    fn from(data: T) -> Self {
        Packet::new(data)
    }
}

impl NetStack {
    pub fn new(config: Config) -> (Self, crate::TcpListener, crate::UdpSocket) {
        let (packet_sender, packet_receiver) = mpsc::channel::<Packet>(config.channel_size);
        let (udp_inbound_app, udp_outbound_stack) = mpsc::channel::<Packet>(config.channel_size);
        let (tcp_inbound_app, tcp_outbound_stack) = mpsc::channel::<Packet>(config.channel_size);
        let buffer_pool = Arc::new(BufferPool::new(
            config.buffer_pool_size,
            config.default_buffer_size,
        ));

        let stack = NetStack {
            udp_inbound: udp_inbound_app,
            tcp_inbound: tcp_inbound_app,
            packet_outbound: packet_receiver,
        };

        (
            stack,
            TcpListener::new(
                tcp_outbound_stack,
                packet_sender.clone(),
                buffer_pool.clone(),
                config,
            ),
            UdpSocket::new(
                udp_outbound_stack,
                packet_sender.clone(),
                buffer_pool.clone(),
            ),
        )
    }

    pub fn split(self) -> (StackSplitSink, StackSplitStream) {
        (
            StackSplitSink::new(self.udp_inbound, self.tcp_inbound),
            StackSplitStream::new(self.packet_outbound),
        )
    }
}

pub struct StackSplitSink {
    udp_inbound: mpsc::Sender<Packet>,
    tcp_inbound: mpsc::Sender<Packet>,
    packet_container: Option<(Packet, IpProtocol)>,
}

impl StackSplitSink {
    pub fn new(udp_inbound: mpsc::Sender<Packet>, tcp_inbound: mpsc::Sender<Packet>) -> Self {
        Self {
            udp_inbound,
            tcp_inbound,
            packet_container: None,
        }
    }
}

impl futures::Sink<Packet> for StackSplitSink {
    type Error = io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.packet_container.is_some() {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        if item.data().is_empty() {
            return Ok(());
        }

        let packet = IpPacket::new_checked(item.data())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let protocol = packet.protocol();
        if matches!(
            protocol,
            IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            self.packet_container.replace((item, protocol));
        } else {
            debug!("tun IP packet ignored (protocol: {protocol:?})");
        }

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let (item, proto) = match self.packet_container.take() {
            Some(val) => val,
            None => return Poll::Ready(Ok(())),
        };

        let sender = match proto {
            IpProtocol::Udp => self.udp_inbound.clone(),
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6 => self.tcp_inbound.clone(),
            _ => {
                debug!("Unsupported protocol for packet: {proto:?}");
                return Poll::Ready(Ok(()));
            }
        };
        let mut fut = Box::pin(sender.reserve());

        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                permit.send(item);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                let msg = format!("Failed to send packet: channel closed for protocol {proto:?}");
                debug!("{}", msg);
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, msg)))
            }
            Poll::Pending => {
                self.packet_container = Some((item, proto));
                Poll::Pending
            }
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub struct StackSplitStream {
    packet_outbound: mpsc::Receiver<Packet>,
}

impl StackSplitStream {
    pub fn new(packet_outbound: mpsc::Receiver<Packet>) -> Self {
        Self { packet_outbound }
    }
}

impl futures::Stream for StackSplitStream {
    type Item = io::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.packet_outbound.poll_recv(cx) {
            Poll::Ready(Some(packet)) => Poll::Ready(Some(Ok(packet))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
