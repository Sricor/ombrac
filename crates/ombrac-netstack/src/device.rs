use std::sync::Arc;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

use crate::stack::{NetStackConfig, Packet};
use crate::warn;
use crate::{buffer::BufferPool, stack::IfaceEvent};

pub struct NetstackDevice {
    rx_sender: mpsc::Sender<Packet>,
    rx_queue: mpsc::Receiver<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

    iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
    buffer_pool: Arc<BufferPool>,
}

impl NetstackDevice {
    pub fn new(
        tx_sender: mpsc::Sender<Packet>,
        iface_notifier: mpsc::Sender<IfaceEvent<'static>>,
        buffer_pool: Arc<BufferPool>,
        config: &NetStackConfig,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = config.mtu;
        capabilities.medium = Medium::Ip;

        let (rx_sender, rx_queue) = mpsc::channel::<Packet>(config.channel_size);

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
            iface_notifier,
            buffer_pool,
        }
    }

    pub fn create_injector(&self) -> mpsc::Sender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let (Ok(packet), Ok(permit)) = (self.rx_queue.try_recv(), self.tx_sender.try_reserve()) {
            let rx_token = RxTokenImpl { packet };
            let tx_token = TxTokenImpl {
                tx_sender: permit,
                buffer_pool: self.buffer_pool.clone(),
            };
            if let Err(e) = self.iface_notifier.try_send(IfaceEvent::DeviceReady) {
                warn!("Failed to notify iface event: {}", e)
            };
            return Some((rx_token, tx_token));
        }

        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl {
                tx_sender: permit,
                buffer_pool: self.buffer_pool.clone(),
            })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl<'a> {
    buffer_pool: Arc<BufferPool>,
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.buffer_pool.get(len);
        buffer.resize(len, 0);

        let result = f(&mut buffer);

        let filled_bytes = buffer.split_to(len);
        let packet = Packet::new(filled_bytes.freeze());
        self.tx_sender.send(packet);

        result
    }
}
