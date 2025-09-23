use std::io::{self, Cursor};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, BufMut, Bytes, BytesMut};

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
    pub fn encode(self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            UdpPacket::Unfragmented { address, data } => {
                buf.put_u8(PACKET_TYPE_UNFRAGMENTED);
                address.write_to(&mut buf);
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
                    addr.write_to(&mut buf);
                }
                buf.put(data);
            }
        }
        buf.freeze()
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
    ) -> Vec<UdpPacket> {
        if data.is_empty() {
            return vec![];
        }

        let mut remaining_data = data;
        let mut chunks = Vec::new();

        // Calculate overhead for the first and subsequent fragments
        let mut addr_buf = BytesMut::new();
        address.write_to(&mut addr_buf);
        let first_frag_overhead = 1 + 2 + 1 + 1 + addr_buf.len(); // Type + ID + Index + Count + Address
        let subsequent_frag_overhead = 1 + 2 + 1 + 1; // Type + ID + Index + Count

        // Split the first chunk
        let first_chunk_size = std::cmp::min(
            remaining_data.len(),
            max_datagram_size.saturating_sub(first_frag_overhead),
        );
        if first_chunk_size == 0 {
            // Cannot even fit the header and 1 byte of data.
            // warn!("Max datagram size too small to send even the first fragment.");
            return vec![];
        }
        chunks.push(remaining_data.split_to(first_chunk_size));

        // Split subsequent chunks
        let subsequent_chunk_size = max_datagram_size.saturating_sub(subsequent_frag_overhead);
        if subsequent_chunk_size > 0 {
            while !remaining_data.is_empty() {
                let chunk_size = std::cmp::min(remaining_data.len(), subsequent_chunk_size);
                chunks.push(remaining_data.split_to(chunk_size));
            }
        }

        if chunks.len() > u8::MAX as usize {
            return vec![];
        }

        let fragment_count = chunks.len() as u8;

        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk_data)| UdpPacket::Fragmented {
                fragment_id,
                fragment_index: i as u8,
                fragment_count,
                address: if i == 0 { Some(address.clone()) } else { None },
                data: chunk_data,
            })
            .collect()
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

    pub fn write_to(&self, buf: &mut BytesMut) {
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
                buf.put_u8(Self::ADDR_TYPE_DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain);
                buf.put_u16(*port);
            }
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
                let mut domain_bytes = vec![0u8; domain_len];
                buf.copy_to_slice(&mut domain_bytes);
                let port = buf.get_u16();
                Ok(Address::Domain(Bytes::from(domain_bytes), port))
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
