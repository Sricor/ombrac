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

// +-------------+-----------------+----------+
// | AddressType |     Address     |   Data   |
// |   (1 byte)  |    (variable)   | (remain) |
// +-------------+-----------------+----------+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub address: Address,
    pub data: Bytes,
}

impl UdpPacket {
    pub fn encode(self) -> Bytes {
        let mut buf = BytesMut::new();
        self.address.write_to(&mut buf);
        buf.put(self.data);
        buf.freeze()
    }

    pub fn decode(buf: Bytes) -> io::Result<Self> {
        let mut cursor = Cursor::new(buf.as_ref());
        let address = Address::read_from(&mut cursor)?;
        let data = buf.slice(cursor.position() as usize..);
        Ok(UdpPacket { address, data })
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
                if buf.remaining() < 4 + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for IPv4 address",
                    ));
                }
                let mut ip_bytes = [0u8; 4];
                buf.copy_to_slice(&mut ip_bytes);
                let ip = Ipv4Addr::from(ip_bytes);
                let port = buf.get_u16();
                Ok(Address::SocketV4(SocketAddrV4::new(ip, port)))
            }
            Self::ADDR_TYPE_IPV6 => {
                if buf.remaining() < 16 + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Not enough data for IPv6 address",
                    ));
                }
                let mut ip_bytes = [0u8; 16];
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
                if buf.remaining() < domain_len + 2 {
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

        if let Some((domain, port_str)) = value.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if domain.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Domain name cannot be empty",
                    ));
                }

                if domain.len() > 255 {
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
        let value = match self {
            Self::Domain(domain, port) => format!("{:?}:{}", domain, port),
            Self::SocketV4(addr) => addr.to_string(),
            Self::SocketV6(addr) => addr.to_string(),
        };

        write!(f, "{value}")
    }
}
