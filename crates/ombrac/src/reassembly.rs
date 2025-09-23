use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::task::JoinHandle;

use crate::protocol::{Address, UdpPacket};

const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

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
        let total_len = self.fragments.iter().map(|f| f.as_ref().unwrap().len()).sum();
        let mut combined = Vec::with_capacity(total_len);
        for fragment in self.fragments.iter_mut() {
            combined.extend_from_slice(fragment.take().unwrap().as_ref());
        }
        (self.address.clone(), Bytes::from(combined))
    }
}

type FragmentID = u16;

pub struct UdpReassembler {
    map: Arc<Mutex<HashMap<FragmentID, ReassemblyBuffer>>>,
    _cleanup_handle: JoinHandle<()>,
}

impl UdpReassembler {
    pub fn new() -> Self {
        let map: Arc<Mutex<HashMap<FragmentID, ReassemblyBuffer>>> = Arc::new(Mutex::new(HashMap::new()));
        let map_clone = Arc::clone(&map);

        let _cleanup_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(REASSEMBLY_TIMEOUT).await;
                let mut map = map_clone.lock().unwrap();
                map.retain(|_, buffer| {
                    if buffer.first_seen.elapsed() > REASSEMBLY_TIMEOUT {
                        // warn!("Dropping stale fragmented packet (id: {}) due to timeout", buffer.address);
                        false
                    } else {
                        true
                    }
                });
            }
        });

        Self {
            map,
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
                let mut map = self.map.lock().unwrap();
                if fragment_index == 0 {
                    if let Some(buffer) = ReassemblyBuffer::new(packet) {
                        map.insert(fragment_id, buffer);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "First fragment packet is malformed",
                        ));
                    }
                } else if let Some(buffer) = map.get_mut(&fragment_id) {
                    buffer.add_fragment(packet);
                } else {
                    // Orphan fragment, just drop it.
                    return Ok(None);
                }

                // Check for completion
                if let Some(buffer) = map.get_mut(&fragment_id) {
                    if buffer.is_complete() {
                        // It's complete, remove from map and return assembled data
                        let mut final_buffer = map.remove(&fragment_id).unwrap();
                        return Ok(Some(final_buffer.assemble()));
                    }
                }
                
                Ok(None)
            }
        }
    }
}