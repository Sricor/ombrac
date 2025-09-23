use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

pub const PROTOCOLS_VERSION: u8 = 0x01;
pub const SECRET_LENGTH: usize = 32;

pub type Secret = [u8; SECRET_LENGTH];

// +-------------+--------------------------------+------------------+------------------------------+
// |   Version   |             Secret             |  Options Length  |           Options            |
// |  (1 byte)   |           (32 bytes)           |     (1 byte)     |  (value of Options Length)   |
// +-------------+--------------------------------+------------------+------------------------------+
// |<-                Fixed-size Header (34 bytes)                 ->|
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u8,
    pub secret: [u8; 32],
    pub options: Bytes,
}

impl ClientHello {
    // Version + Secret + Options_length
    pub const FIXED_HEADER_LEN: usize = 1 + 32 + 1;

    pub fn new(version: u8, secret: [u8; 32], options: Bytes) -> Self {
        Self {
            version,
            secret,
            options,
        }
    }
}

// +-------------+-----------------+
// | AddressType |     Address     |
// |   (1 byte)  |    (variable)   |
// +-------------+-----------------+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConnect {
    pub address: Address,
}

const PACKET_TYPE_UNFRAGMENTED: u8 = 0x00;
const PACKET_TYPE_FRAGMENTED: u8 = 0x01;

// Represents a UDP packet, which can either be a whole datagram
// or a fragment of a larger one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpPacket {
    // +------+---------+------+
    // | Type | Address | Data |
    // +------+---------+------+
    Unfragmented {
        address: Address,
        data: Bytes,
    },
    // +------+-------------+----------------+----------------+-----------+------+
    // | Type | Fragment ID | Fragment Index | Fragment Count | [Address] | Data |
    // +------+-------------+----------------+----------------+-----------+------+
    Fragmented {
        fragment_id: u16,
        fragment_index: u8,
        fragment_count: u8,
        // The address is only present in the first fragment (index 0).
        address: Option<Address>,
        data: Bytes,
    },
}

impl UdpPacket {
    pub fn encode(self) -> io::Result<Bytes> {
        let mut buf = BytesMut::new();
        match self {
            UdpPacket::Unfragmented { address, data } => {
                buf.put_u8(PACKET_TYPE_UNFRAGMENTED);
                address.write_to(&mut buf)?;
                buf.put(data);
            }
            UdpPacket::Fragmented {
                fragment_id,
                fragment_index,
                fragment_count,
                address,
                data,
            } => {
                buf.put_u8(PACKET_TYPE_FRAGMENTED);
                buf.put_u16(fragment_id);
                buf.put_u8(fragment_index);
                buf.put_u8(fragment_count);
                if let Some(addr) = address {
                    addr.write_to(&mut buf)?;
                }
                buf.put(data);
            }
        }
        Ok(buf.freeze())
    }

    pub fn decode(buf: Bytes) -> io::Result<Self> {
        let mut cursor = Cursor::new(buf.as_ref());
        if !cursor.has_remaining() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Empty UDP packet",
            ));
        }

        match cursor.get_u8() {
            PACKET_TYPE_UNFRAGMENTED => {
                let address = Address::read_from(&mut cursor)?;
                let data = buf.slice(cursor.position() as usize..);
                Ok(UdpPacket::Unfragmented { address, data })
            }
            PACKET_TYPE_FRAGMENTED => {
                if cursor.remaining() < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for fragmented header",
                    ));
                }
                let fragment_id = cursor.get_u16();
                let fragment_index = cursor.get_u8();
                let fragment_count = cursor.get_u8();

                let address = if fragment_index == 0 {
                    Some(Address::read_from(&mut cursor)?)
                } else {
                    None
                };

                let data = buf.slice(cursor.position() as usize..);
                Ok(UdpPacket::Fragmented {
                    fragment_id,
                    fragment_index,
                    fragment_count,
                    address,
                    data,
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown UDP packet type",
            )),
        }
    }

    pub fn split_packet(
        address: Address,
        data: Bytes,
        max_datagram_size: usize,
        fragment_id: u16,
    ) -> impl Iterator<Item = UdpPacket> {
        UdpPacketSplitter::new(address, data, max_datagram_size, fragment_id)
    }
}

pub struct UdpPacketSplitter {
    address: Address,
    remaining_data: Bytes,
    max_datagram_size: usize,
    fragment_id: u16,
    fragment_count: u8,
    next_index: u8,
}

impl UdpPacketSplitter {
    pub fn new(address: Address, data: Bytes, max_datagram_size: usize, fragment_id: u16) -> Self {
        // If there's no data to send, create an empty iterator.
        if data.is_empty() {
            return Self {
                address,
                remaining_data: Bytes::new(),
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        let first_frag_overhead = 1 + 2 + 1 + 1 + address.encoded_len();
        let subsequent_frag_overhead = 1 + 2 + 1 + 1;

        // The first fragment must be able to hold its header and at least 1 byte of data.
        let first_chunk_size = max_datagram_size.saturating_sub(first_frag_overhead);
        if first_chunk_size == 0 {
            return Self {
                address,
                remaining_data: data, // Keep original data for consistency
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        let mut num_chunks = 0;
        let remaining_len_after_first = data.len().saturating_sub(first_chunk_size);

        if !data.is_empty() {
            num_chunks = 1;
        }

        let subsequent_chunk_size = max_datagram_size.saturating_sub(subsequent_frag_overhead);
        if subsequent_chunk_size > 0 && remaining_len_after_first > 0 {
            // Ceiling division to calculate how many more chunks are needed.
            num_chunks += remaining_len_after_first.div_ceil(subsequent_chunk_size);
        }

        // The number of fragments cannot exceed what a u8 can hold.
        if num_chunks > u8::MAX as usize {
            return Self {
                address,
                remaining_data: data,
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        Self {
            address,
            remaining_data: data,
            max_datagram_size,
            fragment_id,
            fragment_count: num_chunks as u8,
            next_index: 0,
        }
    }
}

impl Iterator for UdpPacketSplitter {
    type Item = UdpPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.fragment_count || self.remaining_data.is_empty() {
            return None;
        }

        let (overhead, addr_option) = if self.next_index == 0 {
            (
                1 + 2 + 1 + 1 + self.address.encoded_len(),
                Some(self.address.clone()),
            )
        } else {
            (1 + 2 + 1 + 1, None)
        };

        let chunk_size = std::cmp::min(
            self.remaining_data.len(),
            self.max_datagram_size.saturating_sub(overhead),
        );

        if chunk_size == 0 {
            // Should not happen with pre-calculation, but as a safeguard
            return None;
        }

        let chunk_data = self.remaining_data.split_to(chunk_size);
        let packet = UdpPacket::Fragmented {
            fragment_id: self.fragment_id,
            fragment_index: self.next_index,
            fragment_count: self.fragment_count,
            address: addr_option,
            data: chunk_data,
        };

        self.next_index += 1;
        Some(packet)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketV4(SocketAddrV4),
    SocketV6(SocketAddrV6),
    Domain(Bytes, u16),
}

impl Address {
    pub const ADDR_TYPE_IPV4: u8 = 0x01;
    pub const ADDR_TYPE_IPV6: u8 = 0x04;
    pub const ADDR_TYPE_DOMAIN: u8 = 0x03;

    pub const PORT_LEN: usize = 2;
    pub const IPV4_ADDR_LEN: usize = 4;
    pub const IPV6_ADDR_LEN: usize = 16;
    pub const MAX_DOMAIN_LEN: usize = 255;

    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        match self {
            Address::SocketV4(addr) => {
                buf.put_u8(Self::ADDR_TYPE_IPV4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::SocketV6(addr) => {
                buf.put_u8(Self::ADDR_TYPE_IPV6);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::Domain(domain, port) => {
                if domain.len() > Self::MAX_DOMAIN_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Domain name is too long to be encoded: {} bytes (max 255)",
                            domain.len()
                        ),
                    ));
                }
                buf.put_u8(Self::ADDR_TYPE_DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain);
                buf.put_u16(*port);
            }
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> usize {
        // 1 byte for address type
        1 + match self {
            Address::SocketV4(_) => Self::IPV4_ADDR_LEN + Self::PORT_LEN,
            Address::SocketV6(_) => Self::IPV6_ADDR_LEN + Self::PORT_LEN,
            Address::Domain(domain, _) => 1 + domain.len() + Self::PORT_LEN, // 1 byte for domain length
        }
    }

    pub fn read_from(buf: &mut Cursor<&[u8]>) -> io::Result<Self> {
        if !buf.has_remaining() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for address type",
            ));
        }
        let addr_type = buf.get_u8();

        match addr_type {
            Self::ADDR_TYPE_IPV4 => {
                if buf.remaining() < Self::IPV4_ADDR_LEN + Self::PORT_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for IPv4 address",
                    ));
                }
                let mut ip_bytes = [0u8; Self::IPV4_ADDR_LEN];
                buf.copy_to_slice(&mut ip_bytes);
                let ip = Ipv4Addr::from(ip_bytes);
                let port = buf.get_u16();
                Ok(Address::SocketV4(SocketAddrV4::new(ip, port)))
            }
            Self::ADDR_TYPE_IPV6 => {
                if buf.remaining() < Self::IPV6_ADDR_LEN + Self::PORT_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for IPv6 address",
                    ));
                }
                let mut ip_bytes = [0u8; Self::IPV6_ADDR_LEN];
                buf.copy_to_slice(&mut ip_bytes);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = buf.get_u16();
                Ok(Address::SocketV6(SocketAddrV6::new(ip, port, 0, 0)))
            }
            Self::ADDR_TYPE_DOMAIN => {
                if !buf.has_remaining() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for domain length",
                    ));
                }
                let domain_len = buf.get_u8() as usize;
                if buf.remaining() < domain_len + Self::PORT_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for domain and port",
                    ));
                }
                let domain_bytes = buf.copy_to_bytes(domain_len);
                let port = buf.get_u16();
                Ok(Address::Domain(domain_bytes, port))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown address type",
            )),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(addr) => Self::SocketV4(addr),
            SocketAddr::V6(addr) => Self::SocketV6(addr),
        }
    }
}

impl TryFrom<&str> for Address {
    type Error = io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Address::from(addr));
        }

        if let Some((domain, port_str)) = value.rsplit_once(':')
            && let Ok(port) = port_str.parse::<u16>()
        {
            if domain.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Domain name cannot be empty",
                ));
            }

            if domain.len() > Self::MAX_DOMAIN_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Domain name is too long: {} bytes (max 255)", domain.len()),
                ));
            }

            return Ok(Address::Domain(
                Bytes::copy_from_slice(domain.as_bytes()),
                port,
            ));
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid address format: {}", value),
        ))
    }
}

impl TryFrom<String> for Address {
    type Error = io::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Address::try_from(value.as_str())
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(domain, port) => {
                write!(f, "{}:{}", String::from_utf8_lossy(domain), port)
            }
            Self::SocketV4(addr) => write!(f, "{}", addr),
            Self::SocketV6(addr) => write!(f, "{}", addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_data(packets: &[UdpPacket]) -> Bytes {
        let mut parts = Vec::new();
        for p in packets {
            if let UdpPacket::Fragmented { data, .. } = p {
                parts.push(data.clone());
            }
        }
        Bytes::from(parts.concat())
    }

    #[test]
    fn test_splitter_iterator_basic_fragmentation() {
        let addr: Address = "127.0.0.1:8080".parse::<SocketAddr>().unwrap().into();
        let addr_len = addr.encoded_len(); // 1 (type) + 4 (ip) + 2 (port) = 7

        // Overhead: 1 (type) + 2 (id) + 1 (idx) + 1 (count) = 5
        // First fragment overhead = 5 + addr_len = 12
        // Subsequent fragment overhead = 5
        let max_size = 100;

        let first_frag_overhead = 1 + 2 + 1 + 1 + addr_len;
        let subsequent_frag_overhead = 1 + 2 + 1 + 1;

        let first_payload_size = max_size - first_frag_overhead; // 100 - 12 = 88
        let subsequent_payload_size = max_size - subsequent_frag_overhead; // 100 - 5 = 95

        // Total data size: 88 + 95 + 10 = 193
        let data = Bytes::from(vec![1u8; 193]);

        let packets: Vec<_> =
            UdpPacket::split_packet(addr, data.clone(), max_size, 12345).collect();

        // We expect 3 fragments.
        assert_eq!(packets.len(), 3);
        assert_eq!(
            packets.iter().all(|p| {
                if let UdpPacket::Fragmented { fragment_count, .. } = p {
                    *fragment_count == 3
                } else {
                    false
                }
            }),
            true,
            "All fragments should have fragment_count = 3"
        );

        // Check first fragment
        if let UdpPacket::Fragmented {
            fragment_index,
            address,
            data,
            ..
        } = &packets[0]
        {
            assert_eq!(*fragment_index, 0);
            assert!(address.is_some());
            assert_eq!(data.len(), first_payload_size);
        } else {
            panic!("Expected a fragmented packet");
        }

        // Check second fragment
        if let UdpPacket::Fragmented {
            fragment_index,
            address,
            data,
            ..
        } = &packets[1]
        {
            assert_eq!(*fragment_index, 1);
            assert!(address.is_none());
            assert_eq!(data.len(), subsequent_payload_size);
        } else {
            panic!("Expected a fragmented packet");
        }

        // Check third fragment
        if let UdpPacket::Fragmented {
            fragment_index,
            address,
            data,
            ..
        } = &packets[2]
        {
            assert_eq!(*fragment_index, 2);
            assert!(address.is_none());
            assert_eq!(data.len(), 10);
        } else {
            panic!("Expected a fragmented packet");
        }

        // Verify that the reassembled data matches the original.
        assert_eq!(reassemble_data(&packets), data);
    }

    #[test]
    fn test_splitter_single_fragment() {
        let addr: Address = "127.0.0.1:8080".parse::<SocketAddr>().unwrap().into();
        let data = Bytes::from_static(b"this fits in one packet");
        let max_size = 100;

        let packets: Vec<_> = UdpPacket::split_packet(addr, data.clone(), max_size, 1).collect();

        assert_eq!(packets.len(), 1);
        if let UdpPacket::Fragmented {
            fragment_index,
            fragment_count,
            address,
            data: packet_data,
            ..
        } = &packets[0]
        {
            assert_eq!(*fragment_index, 0);
            assert_eq!(*fragment_count, 1);
            assert!(address.is_some());
            assert_eq!(*packet_data, data);
        } else {
            panic!("Expected a fragmented packet");
        }
    }

    #[test]
    fn test_splitter_empty_data_yields_no_packets() {
        let addr: Address = "127.0.0.1:8080".parse::<SocketAddr>().unwrap().into();
        let data = Bytes::new();
        let max_size = 100;

        let packets: Vec<_> = UdpPacket::split_packet(addr, data, max_size, 1).collect();

        // The iterator should be empty for empty data.
        assert!(packets.is_empty());
    }

    #[test]
    fn test_splitter_max_size_too_small_yields_no_packets() {
        let addr: Address = "127.0.0.1:8080".parse::<SocketAddr>().unwrap().into();
        let data = Bytes::from_static(b"some data");
        // Set max_size to be smaller than the header, so no packets can be formed.
        let max_size = 10;

        let packets: Vec<_> = UdpPacket::split_packet(addr, data, max_size, 1).collect();

        // The iterator should be empty if no packets can be formed.
        assert!(packets.is_empty());
    }
}
