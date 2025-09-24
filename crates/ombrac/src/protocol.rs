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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u8,
    pub secret: Secret,
    pub options: Bytes,
}

impl ClientHello {
    pub const FIXED_HEADER_LEN: usize = 1 + SECRET_LENGTH + 1;

    pub fn new(version: u8, secret: Secret, options: Bytes) -> Self {
        Self {
            version,
            secret,
            options,
        }
    }

    pub fn encode(&self, dst: &mut BytesMut) -> io::Result<()> {
        if self.options.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Options length cannot exceed 255 bytes",
            ));
        }
        dst.reserve(Self::FIXED_HEADER_LEN + self.options.len());
        dst.put_u8(self.version);
        dst.put_slice(&self.secret);
        dst.put_u8(self.options.len() as u8);
        dst.put_slice(&self.options);
        Ok(())
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
    // +------+------------+---------+------+
    // | Type | Session ID | Address | Data |
    // +------+------------+---------+------+
    Unfragmented {
        session_id: u64,
        address: Address,
        data: Bytes,
    },
    // +------+------------+-------------+----------------+----------------+-----------+------+
    // | Type | Session ID | Fragment ID | Fragment Index | Fragment Count | [Address] | Data |
    // +------+------------+-------------+----------------+----------------+-----------+------+
    Fragmented {
        session_id: u64,
        fragment_id: u16,
        fragment_index: u8,
        fragment_count: u8,
        address: Option<Address>,
        data: Bytes,
    },
}

impl UdpPacket {
    pub fn encode(self) -> io::Result<Bytes> {
        let mut buf = BytesMut::new();
        match self {
            UdpPacket::Unfragmented {
                session_id,
                address,
                data,
            } => {
                buf.put_u8(PACKET_TYPE_UNFRAGMENTED);
                buf.put_u64(session_id);
                address.write_to(&mut buf)?;
                buf.put(data);
            }
            UdpPacket::Fragmented {
                session_id,
                fragment_id,
                fragment_index,
                fragment_count,
                address,
                data,
            } => {
                buf.put_u8(PACKET_TYPE_FRAGMENTED);
                buf.put_u64(session_id);
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
        if cursor.remaining() < 1 + 8 {
            // Type + Session ID
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Empty or incomplete UDP packet",
            ));
        }

        let packet_type = cursor.get_u8();
        let session_id = cursor.get_u64();

        match packet_type {
            PACKET_TYPE_UNFRAGMENTED => {
                let address = Address::read_from(&mut cursor)?;
                let data = buf.slice(cursor.position() as usize..);
                Ok(UdpPacket::Unfragmented {
                    session_id,
                    address,
                    data,
                })
            }
            PACKET_TYPE_FRAGMENTED => {
                if cursor.remaining() < 4 {
                    // Fragment ID + Index + Count
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
                    session_id,
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
        session_id: u64,
        address: Address,
        data: Bytes,
        max_datagram_size: usize,
        fragment_id: u16,
    ) -> impl Iterator<Item = UdpPacket> {
        UdpPacketSplitter::new(session_id, address, data, max_datagram_size, fragment_id)
    }
}

pub struct UdpPacketSplitter {
    session_id: u64,
    address: Address,
    remaining_data: Bytes,
    max_datagram_size: usize,
    fragment_id: u16,
    fragment_count: u8,
    next_index: u8,
}

impl UdpPacketSplitter {
    pub fn new(
        session_id: u64,
        address: Address,
        data: Bytes,
        max_datagram_size: usize,
        fragment_id: u16,
    ) -> Self {
        if data.is_empty() {
            return Self {
                session_id,
                address,
                remaining_data: Bytes::new(),
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        // Overhead includes: type(1) + session_id(8) + fragment_id(2) + index(1) + count(1)
        const BASE_FRAG_OVERHEAD: usize = 1 + 8 + 2 + 1 + 1;
        let first_frag_overhead = BASE_FRAG_OVERHEAD + address.encoded_len();
        let subsequent_frag_overhead = BASE_FRAG_OVERHEAD;

        let first_chunk_size = max_datagram_size.saturating_sub(first_frag_overhead);
        if first_chunk_size == 0 {
            return Self {
                session_id,
                address,
                remaining_data: Bytes::new(), // Clear data to ensure it's an empty iterator
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        let mut num_chunks = 1;
        let remaining_len_after_first = data.len().saturating_sub(first_chunk_size);

        let subsequent_chunk_size = max_datagram_size.saturating_sub(subsequent_frag_overhead);
        if subsequent_chunk_size > 0 && remaining_len_after_first > 0 {
            num_chunks += remaining_len_after_first.div_ceil(subsequent_chunk_size);
        } else if remaining_len_after_first > 0 {
            // Not enough space for subsequent fragments
            return Self {
                session_id,
                address,
                remaining_data: Bytes::new(),
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        if num_chunks > u8::MAX as usize {
            return Self {
                session_id,
                address,
                remaining_data: Bytes::new(),
                max_datagram_size,
                fragment_id,
                fragment_count: 0,
                next_index: 0,
            };
        }

        Self {
            session_id,
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

        const BASE_FRAG_OVERHEAD: usize = 1 + 8 + 2 + 1 + 1;
        let (overhead, addr_option) = if self.next_index == 0 {
            (
                BASE_FRAG_OVERHEAD + self.address.encoded_len(),
                Some(self.address.clone()),
            )
        } else {
            (BASE_FRAG_OVERHEAD, None)
        };

        let chunk_size = std::cmp::min(
            self.remaining_data.len(),
            self.max_datagram_size.saturating_sub(overhead),
        );

        if chunk_size == 0 {
            self.fragment_count = 0;
            return None;
        }

        let chunk_data = self.remaining_data.split_to(chunk_size);
        let packet = UdpPacket::Fragmented {
            session_id: self.session_id,
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
        1 + match self {
            Address::SocketV4(_) => Self::IPV4_ADDR_LEN + Self::PORT_LEN,
            Address::SocketV6(_) => Self::IPV6_ADDR_LEN + Self::PORT_LEN,
            Address::Domain(domain, _) => 1 + domain.len() + Self::PORT_LEN,
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

        if let Some((domain, port_str)) = value.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
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
