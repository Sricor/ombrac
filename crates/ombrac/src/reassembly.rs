use bytes::Bytes;
use dashmap::DashMap;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

use crate::protocol::{Address, UdpPacket};

const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONCURRENT_REASSEMBLIES: usize = 8192;

struct ReassemblyBuffer {
    fragments: Vec<Option<Bytes>>,
    received_count: u8,
    total_count: u8,
    address: Address,
    first_seen: Instant,
}

impl ReassemblyBuffer {
    fn new(first_fragment: UdpPacket) -> Option<Self> {
        if let UdpPacket::Fragmented {
            fragment_index: 0,
            fragment_count,
            address: Some(address),
            data,
            ..
        } = first_fragment
        {
            let mut fragments = vec![None; fragment_count as usize];
            fragments[0] = Some(data);
            Some(Self {
                fragments,
                received_count: 1,
                total_count: fragment_count,
                address,
                first_seen: Instant::now(),
            })
        } else {
            None
        }
    }

    fn add_fragment(&mut self, fragment: UdpPacket) {
        if let UdpPacket::Fragmented {
            fragment_index,
            data,
            ..
        } = fragment
        {
            let index = fragment_index as usize;
            if index < self.fragments.len() && self.fragments[index].is_none() {
                self.fragments[index] = Some(data);
                self.received_count += 1;
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.received_count == self.total_count
    }

    fn assemble(&mut self) -> (Address, Bytes) {
        let total_len = self
            .fragments
            .iter()
            .map(|f| f.as_ref().unwrap().len())
            .sum();
        let mut combined = Vec::with_capacity(total_len);
        for fragment in self.fragments.iter_mut() {
            combined.extend_from_slice(fragment.take().unwrap().as_ref());
        }
        (self.address.clone(), Bytes::from(combined))
    }
}

type FragmentID = u16;

pub struct UdpReassembler {
    map: Arc<DashMap<FragmentID, ReassemblyBuffer>>,
    max_concurrent_reassemblies: usize,
    _cleanup_handle: JoinHandle<()>,
}

impl Default for UdpReassembler {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_CONCURRENT_REASSEMBLIES,
            DEFAULT_REASSEMBLY_TIMEOUT,
        )
    }
}

impl UdpReassembler {
    pub fn new(max_concurrent_reassemblies: usize, reassembly_timeout: Duration) -> Self {
        let map = Arc::new(DashMap::with_capacity(max_concurrent_reassemblies));
        let map_clone = Arc::clone(&map);

        let _cleanup_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(reassembly_timeout).await;
                map_clone.retain(|_id, buffer: &mut ReassemblyBuffer| {
                    buffer.first_seen.elapsed() <= reassembly_timeout
                });
            }
        });

        Self {
            map,
            max_concurrent_reassemblies,
            _cleanup_handle,
        }
    }

    pub fn process(&self, packet: UdpPacket) -> io::Result<Option<(Address, Bytes)>> {
        match packet {
            UdpPacket::Unfragmented { address, data } => Ok(Some((address, data))),
            UdpPacket::Fragmented {
                fragment_id,
                fragment_index,
                ..
            } => {
                if fragment_index == 0 {
                    if self.map.len() >= self.max_concurrent_reassemblies {
                        return Ok(None);
                    }

                    if let Some(buffer) = ReassemblyBuffer::new(packet) {
                        self.map.insert(fragment_id, buffer);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "First fragment packet is malformed",
                        ));
                    }
                } else if let Some(mut buffer) = self.map.get_mut(&fragment_id) {
                    buffer.add_fragment(packet);
                } else {
                    return Ok(None);
                }

                if let Some(buffer) = self.map.get(&fragment_id)
                    && buffer.is_complete()
                        && let Some((_, mut final_buffer)) = self.map.remove(&fragment_id) {
                            return Ok(Some(final_buffer.assemble()));
                        }

                Ok(None)
            }
        }
    }
}
