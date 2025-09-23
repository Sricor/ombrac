use std::io::Cursor;

use bytes::{Buf, BufMut, BytesMut};
pub use tokio_util::codec::{Decoder, Encoder};

use crate::protocol::{Address, ClientConnect, ClientHello};

/// Represents the two types of messages that can be sent upstream.
/// The protocol is designed as follows:
///
/// A single byte message type header, followed by the message payload.
/// - 0x01: Hello
/// - 0x02: Connect
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamMessage {
    Hello(ClientHello),
    Connect(ClientConnect),
}

const MSG_TYPE_HELLO: u8 = 0x01;
const MSG_TYPE_CONNECT: u8 = 0x02;

pub struct ProtocolCodec;

impl Decoder for ProtocolCodec {
    type Item = UpstreamMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&src[..]);

        match cursor.get_u8() {
            MSG_TYPE_HELLO => {
                let header_len = 1 + ClientHello::FIXED_HEADER_LEN;
                if src.len() < header_len {
                    return Ok(None);
                }

                let options_len = src[34] as usize;
                let total_len = header_len + options_len;

                if src.len() < total_len {
                    return Ok(None);
                }

                src.advance(1);

                let version = src.get_u8();
                let mut secret = [0u8; 32];
                src.copy_to_slice(&mut secret);
                src.advance(1);

                let options = src.split_to(options_len).freeze();

                Ok(Some(UpstreamMessage::Hello(ClientHello {
                    version,
                    secret,
                    options,
                })))
            }
            MSG_TYPE_CONNECT => {
                let addr_result = Address::read_from(&mut cursor);

                match addr_result {
                    Ok(address) => {
                        let total_len = cursor.position() as usize;
                        src.advance(total_len);
                        Ok(Some(UpstreamMessage::Connect(ClientConnect { address })))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                    Err(e) => Err(e),
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message type",
            )),
        }
    }
}

impl Encoder<UpstreamMessage> for ProtocolCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: UpstreamMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            UpstreamMessage::Hello(hello) => {
                if hello.options.len() > u8::MAX as usize {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Options length cannot exceed 255 bytes",
                    ));
                }
                dst.reserve(1 + ClientHello::FIXED_HEADER_LEN + hello.options.len());
                dst.put_u8(MSG_TYPE_HELLO);
                dst.put_u8(hello.version);
                dst.put_slice(&hello.secret);
                dst.put_u8(hello.options.len() as u8);
                dst.put_slice(&hello.options);
            }
            UpstreamMessage::Connect(connect) => {
                dst.reserve(1 + 1 + 16 + 2);
                dst.put_u8(MSG_TYPE_CONNECT);
                connect.address.write_to(dst)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};

    use crate::protocol::PROTOCOLS_VERSION;
    use bytes::Bytes;

    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let mut codec = ProtocolCodec;
        let options_data = Bytes::from_static(b"some_options_here");
        let message = UpstreamMessage::Hello(ClientHello {
            version: PROTOCOLS_VERSION,
            secret: [255; 32],
            options: options_data.clone(),
        });

        let mut buf = BytesMut::new();
        codec.encode(message.clone(), &mut buf).unwrap();

        // 1 (type) + 1 (ver) + 32 (secret) + 1 (opts_len) + N (opts)
        assert_eq!(buf.len(), 1 + 1 + 32 + 1 + options_data.len());
        // Message Type
        assert_eq!(buf[0], MSG_TYPE_HELLO);
        // Options Length
        assert_eq!(buf[34], options_data.len() as u8);

        let decoded_message = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(message, decoded_message);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_connect_ipv4_roundtrip() {
        let mut codec = ProtocolCodec;
        let addr = "192.168.1.1:8080".parse::<SocketAddrV4>().unwrap();
        let message = UpstreamMessage::Connect(ClientConnect {
            address: Address::SocketV4(addr),
        });

        let mut buf = BytesMut::new();
        codec.encode(message.clone(), &mut buf).unwrap();

        // 1 (type) + 1 (addr_type) + 4 (ip) + 2 (port)
        assert_eq!(buf.len(), 8);

        let decoded_message = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(message, decoded_message);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_connect_domain_roundtrip() {
        let mut codec = ProtocolCodec;
        let domain = Bytes::from_static(b"example.com");
        let port = 443;
        let message = UpstreamMessage::Connect(ClientConnect {
            address: Address::Domain(domain.clone(), port),
        });

        let mut buf = BytesMut::new();
        codec.encode(message.clone(), &mut buf).unwrap();

        // 1 (type) + 1 (addr_type) + 1 (domain_len) + N (domain) + 2 (port)
        assert_eq!(buf.len(), 1 + 1 + 1 + domain.len() + 2);

        let decoded_message = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(message, decoded_message);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_waits_for_full_header_and_body() {
        let mut codec = ProtocolCodec;
        let options_data = Bytes::from_static(b"12345");
        let message = UpstreamMessage::Hello(ClientHello {
            version: 1,
            secret: [1; 32],
            options: options_data.clone(),
        });

        let mut buf = BytesMut::new();
        codec.encode(message, &mut buf).unwrap();
        // Total length = 1 (type) + 34 (header) + 5 (options) = 40

        // Split buffer to simulate partial reads
        let mut part1 = buf.split_to(10);
        assert!(
            codec.decode(&mut part1).unwrap().is_none(),
            "Should be None with only 10 bytes"
        );

        let part2 = buf.split_to(25); // 10 + 25 = 35 bytes now, still not enough for body
        part1.unsplit(part2);
        assert_eq!(part1.len(), 35);
        assert!(
            codec.decode(&mut part1).unwrap().is_none(),
            "Should be None with full header but no body"
        );

        part1.unsplit(buf); // Add remaining 5 bytes
        assert_eq!(part1.len(), 40);
        let decoded = codec.decode(&mut part1).unwrap();
        assert!(
            decoded.is_some(),
            "Should decode successfully with full message"
        );
        assert!(
            part1.is_empty(),
            "Buffer should be empty after successful decode"
        );
    }

    #[test]
    fn test_encode_error_on_long_options() {
        let mut codec = ProtocolCodec;
        let long_options = Bytes::from(vec![0; 256]); // 256 > u8::MAX
        let message = UpstreamMessage::Hello(ClientHello {
            version: 1,
            secret: [1; 32],
            options: long_options,
        });

        let mut buf = BytesMut::new();
        let result = codec.encode(message, &mut buf);
        assert!(matches!(result, Err(e) if e.kind() == std::io::ErrorKind::InvalidInput));
    }

    #[test]
    fn test_connect_ipv6_roundtrip() {
        let mut codec = ProtocolCodec;
        let addr = "[::1]:8080".parse::<SocketAddrV6>().unwrap();
        let message = UpstreamMessage::Connect(ClientConnect {
            address: Address::SocketV6(addr),
        });

        let mut buf = BytesMut::new();
        codec.encode(message.clone(), &mut buf).unwrap();

        // 1 (type) + 1 (addr_type) + 16 (ip) + 2 (port)
        assert_eq!(buf.len(), 20);

        let decoded_message = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(message, decoded_message);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_invalid_message_type() {
        let mut codec = ProtocolCodec;
        let mut buf = BytesMut::from(&[0xFFu8, 0x01u8, 0x02u8, 0x03u8] as &[u8]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(e) if e.kind() == std::io::ErrorKind::InvalidData));
    }
}
