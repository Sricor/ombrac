use bincode::config::Configuration;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::LazyLock,
};

pub const PROTOCOLS_VERSION: u8 = 0x01;
pub const SECRET_LENGTH: usize = 32;
pub type Secret = [u8; SECRET_LENGTH];

static BINCODE_CONFIG: LazyLock<Configuration> = LazyLock::new(bincode::config::standard);

pub fn encode<T: Serialize>(message: &T) -> io::Result<Bytes> {
    bincode::serde::encode_to_vec(message, *BINCODE_CONFIG)
        .map(Bytes::from)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> io::Result<T> {
    bincode::serde::borrow_decode_from_slice(bytes, *BINCODE_CONFIG)
        .map(|(msg, _)| msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

mod serde_bytes_helper {
    use super::*;

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(Bytes::from(vec))
    }
}

// CHANGED: Add Serialize and Deserialize derives
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub secret: Secret,
    // NEW: Use our helper to handle Bytes serialization
    #[serde(with = "serde_bytes_helper")]
    pub options: Bytes,
}

// REMOVED: All manual encoding logic like `encode` and `FIXED_HEADER_LEN` is no longer needed.

// CHANGED: Add Serialize and Deserialize derives
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConnect {
    pub address: Address,
}

// --- UdpPacket and Address structs ---
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpPacket {
    Unfragmented {
        session_id: u64,
        address: Address,
        #[serde(with = "serde_bytes_helper")]
        data: Bytes,
    },
    Fragmented {
        session_id: u64,
        fragment_id: u16,
        fragment_index: u8,
        fragment_count: u8,
        address: Option<Address>,
        #[serde(with = "serde_bytes_helper")]
        data: Bytes,
    },
}

impl UdpPacket {
    pub fn encode(&self) -> io::Result<Bytes> {
        encode(self)
    }

    pub fn decode(bytes: Bytes) -> io::Result<Self> {
        decode(&bytes)
    }

    pub fn split_packet(
        session_id: u64,
        address: Address,
        data: Bytes,
        max_payload_size: usize,
        fragment_id: u16,
    ) -> impl Iterator<Item = UdpPacket> {
        let data_chunks: Vec<Bytes> = data
            .chunks(max_payload_size)
            .map(Bytes::copy_from_slice)
            .collect();
        let fragment_count = data_chunks.len() as u8;

        data_chunks.into_iter().enumerate().map(move |(i, chunk)| {
            let fragment_index = i as u8;
            UdpPacket::Fragmented {
                session_id,
                fragment_id,
                fragment_index,
                fragment_count,
                address: if fragment_index == 0 {
                    Some(address.clone())
                } else {
                    None
                },
                data: chunk,
            }
        })
    }
}

// CHANGED: Add Serialize, Deserialize derives
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketV4(SocketAddrV4),
    SocketV6(SocketAddrV6),
    Domain(#[serde(with = "serde_bytes_helper")] Bytes, u16),
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
        match self {
            Self::Domain(domain, port) => {
                write!(f, "{}:{}", String::from_utf8_lossy(domain), port)
            }
            Self::SocketV4(addr) => write!(f, "{}", addr),
            Self::SocketV6(addr) => write!(f, "{}", addr),
        }
    }
}
