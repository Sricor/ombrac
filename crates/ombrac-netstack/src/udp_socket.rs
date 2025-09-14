use etherparse::PacketBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::buffer::BufferPool;
use crate::{Packet, packet::IpPacket};
use crate::{error, trace};

pub struct UdpPacket {
    pub data: Packet,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::Receiver<Packet>,
    outbound: mpsc::Sender<Packet>,
    buffer_pool: Arc<BufferPool>,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        buffer_pool: Arc<BufferPool>,
    ) -> Self {
        Self {
            inbound,
            outbound,
            buffer_pool,
        }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead { recv: self.inbound };
        let write = SplitWrite {
            send: self.outbound,
            buffer_pool: self.buffer_pool,
        };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<Packet>,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.recv.recv().await.and_then(|data| {
            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    return None;
                }
            };

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match smoltcp::wire::UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!(
                        "invalid err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, \
                         payload: {payload:?}"
                    );
                    return None;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("created UDP socket for {src_addr} <-> {dst_addr}");

            Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            })
        })
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
    buffer_pool: Arc<BufferPool>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        if packet.data.data().is_empty() {
            return Ok(());
        }

        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut buffer = self.buffer_pool.get(builder.size(packet.data.data().len()));
        builder
            .write(&mut buffer, packet.data.data())
            .map_err(std::io::Error::other)?;
        let final_bytes = buffer.split().freeze();

        match self.send.send(Packet::new(final_bytes)).await {
            Ok(()) => Ok(()),
            Err(err) => Err(std::io::Error::other(format!("send error: {err}"))),
        }
    }
}
