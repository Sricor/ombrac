use bytes::{Buf, BufMut};
use std::net::SocketAddr;

/// V4: 4 (type) + 4 (ip) + 2 (port) = 7 bytes
/// V6: 6 (type) + 16 (ip) + 2 (port) = 19 bytes
pub fn encode_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
    }
    buf
}

pub fn decode_addr(mut buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let addr_type = buf.get_u8();
    match addr_type {
        4 => {
            if buf.len() < 6 {
                return None;
            }
            let ip_bytes: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            buf.advance(4);
            let port = buf.get_u16();
            let addr = SocketAddr::new(ip_bytes.into(), port);
            Some((addr, buf))
        }
        6 => {
            if buf.len() < 18 {
                return None;
            }
            let ip_bytes: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            buf.advance(16);
            let port = buf.get_u16();
            let addr = SocketAddr::new(ip_bytes.into(), port);
            Some((addr, buf))
        }
        _ => None,
    }
}
