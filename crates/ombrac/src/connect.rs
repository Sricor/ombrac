use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::address::Address;
use crate::{Secret, SECRET_LENGTH};

pub struct Connect {
    pub secret: Secret,
    pub address: Address,
}

impl Connect {
    pub fn with<A: Into<Address>>(secret: Secret, addr: A) -> Self {
        Self {
            secret,
            address: addr.into(),
        }
    }

    pub fn to_bytes(&self) -> io::Result<Bytes> {
        let address_bytes = self.address.to_bytes()?;

        let total_len = SECRET_LENGTH + address_bytes.len();
        let mut buffer = BytesMut::with_capacity(total_len);

        buffer.put_slice(&self.secret);
        buffer.put_slice(&address_bytes);

        Ok(buffer.freeze())
    }

    pub fn from_bytes<B: Buf>(buf: &mut B) -> io::Result<Self> {
        if buf.remaining() < SECRET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient data for secret",
            ));
        }

        let mut secret = [0u8; SECRET_LENGTH];
        buf.copy_to_slice(&mut secret);

        let address = Address::from_bytes(buf)?;

        Ok(Self { secret, address })
    }

    pub async fn from_async_read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut secret = [0u8; SECRET_LENGTH];
        reader.read_exact(&mut secret).await?;

        let mut address_buf = BytesMut::new();
        let address = Address::from_async_read(reader, &mut address_buf).await?;

        Ok(Self { secret, address })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::io::Cursor;

//     #[tokio::test]
//     async fn test_domain_request() {
//         let secret = [0u8; 32];
//         let domain = "example.com".to_string();
//         let port = 80;
//         let request = Request::TcpConnect(secret, Address::Domain(domain.clone(), port));

//         let bytes: Vec<u8> = request.into();
//         let mut cursor = Cursor::new(bytes);
//         let parsed_request = Request::read(&mut cursor).await.unwrap();

//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::Domain(parsed_domain, parsed_port)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(domain, parsed_domain);
//                 assert_eq!(port, parsed_port);
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     #[tokio::test]
//     async fn test_ipv4_request() {
//         let secret = [0u8; 32];
//         let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);
//         let request = Request::TcpConnect(secret, Address::IPv4(addr));

//         let bytes: Vec<u8> = request.into();
//         let mut cursor = Cursor::new(bytes);
//         let parsed_request = Request::read(&mut cursor).await.unwrap();

//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::IPv4(parsed_addr)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(addr.ip(), parsed_addr.ip());
//                 assert_eq!(addr.port(), parsed_addr.port());
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     #[tokio::test]
//     async fn test_ipv6_request() {
//         let secret = [0u8; 32];
//         let addr = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080, 0, 0);
//         let request = Request::TcpConnect(secret, Address::IPv6(addr));

//         let bytes: Vec<u8> = request.into();
//         let mut cursor = Cursor::new(bytes);
//         let parsed_request = Request::read(&mut cursor).await.unwrap();

//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::IPv6(parsed_addr)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(addr.ip(), parsed_addr.ip());
//                 assert_eq!(addr.port(), parsed_addr.port());
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     #[tokio::test]
//     async fn test_max_length_domain() {
//         let secret = [0u8; 32];
//         let domain = format!("{}.{}", "a".repeat(63), "b".repeat(189));
//         let port = 80;
//         let request = Request::TcpConnect(secret, Address::Domain(domain.clone(), port));

//         let bytes: Vec<u8> = request.into();
//         let mut cursor = Cursor::new(bytes);
//         let parsed_request = Request::read(&mut cursor).await.unwrap();

//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::Domain(parsed_domain, parsed_port)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(domain, parsed_domain);
//                 assert_eq!(port, parsed_port);
//                 assert_eq!(domain.len(), 253);
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     #[tokio::test]
//     async fn test_special_chars_domain() {
//         let secret = [0u8; 32];
//         let special_domains = vec![
//             "hello-world.com",
//             "test.domain.com",
//             "xn--h28h.com",
//             "subdomain.测试.com",
//             "_acme-challenge.example.com",
//             "domain-with-Port.com",
//             "s3.bucket.aws.amazon.com",
//         ];

//         for domain in special_domains {
//             let port = 443;
//             let request = Request::TcpConnect(secret, Address::Domain(domain.to_string(), port));

//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match parsed_request {
//                 Request::TcpConnect(parsed_secret, Address::Domain(parsed_domain, parsed_port)) => {
//                     assert_eq!(secret, parsed_secret);
//                     assert_eq!(domain, parsed_domain);
//                     assert_eq!(port, parsed_port);
//                 }
//                 _ => panic!("Wrong request type for domain: {}", domain),
//             }
//         }
//     }

//     #[tokio::test]
//     async fn test_edge_case_ports() {
//         let secret = [0u8; 32];
//         let edge_ports = vec![0, 1, 80, 443, 8080, 65535];
//         for port in edge_ports {
//             let ipv4_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
//             let request = Request::TcpConnect(secret, Address::IPv4(ipv4_addr));

//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match parsed_request {
//                 Request::TcpConnect(parsed_secret, Address::IPv4(parsed_addr)) => {
//                     assert_eq!(secret, parsed_secret);
//                     assert_eq!(port, parsed_addr.port());
//                 }
//                 _ => panic!("Wrong request type"),
//             }

//             let ipv6_addr = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), port, 0, 0);
//             let request = Request::TcpConnect(secret, Address::IPv6(ipv6_addr));

//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match parsed_request {
//                 Request::TcpConnect(parsed_secret, Address::IPv6(parsed_addr)) => {
//                     assert_eq!(secret, parsed_secret);
//                     assert_eq!(port, parsed_addr.port());
//                 }
//                 _ => panic!("Wrong request type"),
//             }
//         }
//     }

//     #[tokio::test]
//     async fn test_special_ipv4_addresses() {
//         let secret = [0u8; 32];
//         let special_ips = vec![
//             Ipv4Addr::new(0, 0, 0, 0),
//             Ipv4Addr::new(127, 0, 0, 1),
//             Ipv4Addr::new(255, 255, 255, 255),
//             Ipv4Addr::new(192, 168, 0, 1),
//             Ipv4Addr::new(10, 0, 0, 1),
//             Ipv4Addr::new(172, 16, 0, 1),
//         ];

//         for ip in special_ips {
//             let addr = SocketAddrV4::new(ip, 80);
//             let request = Request::TcpConnect(secret, Address::IPv4(addr));

//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match parsed_request {
//                 Request::TcpConnect(parsed_secret, Address::IPv4(parsed_addr)) => {
//                     assert_eq!(secret, parsed_secret);
//                     assert_eq!(addr.ip(), parsed_addr.ip());
//                     assert_eq!(addr.port(), parsed_addr.port());
//                 }
//                 _ => panic!("Wrong request type"),
//             }
//         }
//     }

//     #[tokio::test]
//     async fn test_special_ipv6_addresses() {
//         let secret = [0u8; 32];
//         let special_ips = vec![
//             Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),          // ::
//             Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),          // ::1
//             Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),     // link-local
//             Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), // documentation
//             Ipv6Addr::UNSPECIFIED,
//             Ipv6Addr::LOCALHOST,
//         ];

//         for ip in special_ips {
//             let addr = SocketAddrV6::new(ip, 80, 0, 0);
//             let request = Request::TcpConnect(secret, Address::IPv6(addr));

//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match parsed_request {
//                 Request::TcpConnect(parsed_secret, Address::IPv6(parsed_addr)) => {
//                     assert_eq!(secret, parsed_secret);
//                     assert_eq!(addr.ip(), parsed_addr.ip());
//                     assert_eq!(addr.port(), parsed_addr.port());
//                 }
//                 _ => panic!("Wrong request type"),
//             }
//         }
//     }

//     #[tokio::test]
//     async fn test_partial_read() {
//         let secret = [0u8; 32];
//         let request = Request::TcpConnect(secret, Address::Domain("example.com".to_string(), 80));
//         let bytes: Vec<u8> = request.into();

//         let partial_bytes = &bytes[..bytes.len() - 1];
//         let mut cursor = Cursor::new(partial_bytes);

//         let result = Request::read(&mut cursor).await;
//         assert!(result.is_err());
//     }

//     #[tokio::test]
//     async fn test_empty_domain() {
//         let secret = [0u8; 32];
//         let request = Request::TcpConnect(secret, Address::Domain("".to_string(), 80));
//         let bytes: Vec<u8> = request.into();
//         let mut cursor = Cursor::new(bytes);

//         let parsed_request = Request::read(&mut cursor).await.unwrap();
//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::Domain(domain, port)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(domain, "");
//                 assert_eq!(port, 80);
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     #[tokio::test]
//     async fn test_request_roundtrip() {
//         let secret = [0u8; 32];
//         let test_cases = vec![
//             Request::TcpConnect(secret, Address::Domain("example.com".to_string(), 80)),
//             Request::TcpConnect(
//                 secret,
//                 Address::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
//             ),
//             Request::TcpConnect(
//                 secret,
//                 Address::IPv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
//             ),
//         ];

//         for original_request in test_cases {
//             let bytes: Vec<u8> = original_request.clone().into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             let original_bytes: Vec<u8> = original_request.into();
//             let parsed_bytes: Vec<u8> = parsed_request.into();
//             assert_eq!(original_bytes, parsed_bytes);
//         }
//     }
// }

// #[cfg(test)]
// mod advanced_tests {
//     use super::*;

//     use std::io::Cursor;

//     // Concurrent testing
//     #[tokio::test]
//     async fn test_concurrent_requests() {
//         use futures::future::join_all;
//         use std::sync::Arc;

//         let secret = [0u8; 32];

//         // Test data
//         let requests = vec![
//             Request::TcpConnect(secret, Address::Domain("example.com".to_string(), 80)),
//             Request::TcpConnect(
//                 secret,
//                 Address::IPv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
//             ),
//             Request::TcpConnect(
//                 secret,
//                 Address::IPv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
//             ),
//         ];

//         let requests = Arc::new(requests);

//         // Create multiple concurrent tasks
//         let mut tasks = Vec::new();
//         for _ in 0..100 {
//             let requests = Arc::clone(&requests);
//             let task = tokio::spawn(async move {
//                 for request in requests.iter() {
//                     // Serialize
//                     let bytes: Vec<u8> = request.clone().into();

//                     // Deserialize
//                     let mut cursor = Cursor::new(bytes);
//                     let _ = Request::read(&mut cursor).await.unwrap();
//                 }
//             });
//             tasks.push(task);
//         }

//         // Wait for all tasks to complete
//         let results = join_all(tasks).await;

//         // Verify all tasks completed successfully
//         for result in results {
//             assert!(result.is_ok());
//         }
//     }

//     // Stress testing with large data
//     #[tokio::test]
//     async fn test_large_domain_stress() {
//         let secret = [0u8; 32];

//         // Create a large number of requests with varying domain lengths
//         let domains = (1..100).map(|i| {
//             let domain = format!("{}.example.com", "a".repeat(i));
//             Request::TcpConnect(secret, Address::Domain(domain, 80))
//         });

//         for request in domains {
//             let bytes: Vec<u8> = request.clone().into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed_request = Request::read(&mut cursor).await.unwrap();

//             match (request, parsed_request) {
//                 (
//                     Request::TcpConnect(orig_secret, Address::Domain(orig_domain, orig_port)),
//                     Request::TcpConnect(parsed_secret, Address::Domain(parsed_domain, parsed_port)),
//                 ) => {
//                     assert_eq!(orig_secret, parsed_secret);
//                     assert_eq!(orig_domain, parsed_domain);
//                     assert_eq!(orig_port, parsed_port);
//                 }
//                 _ => panic!("Request type mismatch in stress test"),
//             }
//         }
//     }

//     // Memory allocation failure simulation
//     #[tokio::test]
//     async fn test_allocation_limits() {
//         use std::alloc::{GlobalAlloc, Layout, System};
//         use std::sync::atomic::{AtomicUsize, Ordering};

//         // Custom allocator that fails after N allocations
//         struct _LimitedAllocator {
//             inner: System,
//             remaining: AtomicUsize,
//         }

//         unsafe impl GlobalAlloc for _LimitedAllocator {
//             unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
//                 if self.remaining.fetch_sub(1, Ordering::SeqCst) == 0 {
//                     std::ptr::null_mut()
//                 } else {
//                     self.inner.alloc(layout)
//                 }
//             }

//             unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
//                 self.inner.dealloc(ptr, layout)
//             }
//         }

//         // Test with limited allocations
//         static _LIMITED_ALLOCATOR: _LimitedAllocator = _LimitedAllocator {
//             inner: System,
//             remaining: AtomicUsize::new(10),
//         };

//         // Try to create and process a request with limited memory
//         let result = std::panic::catch_unwind(|| {
//             let request =
//                 Request::TcpConnect([0u8; 32], Address::Domain("test.com".to_string(), 80));
//             let _bytes: Vec<u8> = request.into();
//         });

//         // Verify that we either completed successfully or got an allocation error
//         assert!(result.is_ok() || result.is_err());
//     }
// }

// #[cfg(test)]
// mod edge_case_tests {
//     use super::*;
//     use std::{
//         io::Cursor,
//         pin::Pin,
//         task::{Context, Poll},
//     };
//     use tokio::time::{Duration, Instant};

//     // Rate limited reader that adds artificial delay between reads
//     struct RateLimitedReader<R> {
//         inner: R,
//         delay: Duration,
//         next_read: Option<Instant>,
//     }

//     impl<R: AsyncRead + Unpin> RateLimitedReader<R> {
//         fn new(inner: R, delay: Duration) -> Self {
//             Self {
//                 inner,
//                 delay,
//                 next_read: None,
//             }
//         }
//     }

//     impl<R: AsyncRead + Unpin> AsyncRead for RateLimitedReader<R> {
//         fn poll_read(
//             mut self: Pin<&mut Self>,
//             cx: &mut Context<'_>,
//             buf: &mut tokio::io::ReadBuf<'_>,
//         ) -> Poll<io::Result<()>> {
//             let now = Instant::now();

//             if let Some(next_read) = self.next_read {
//                 if now < next_read {
//                     // Not ready to read yet
//                     cx.waker().wake_by_ref();
//                     return Poll::Pending;
//                 }
//             }

//             // Attempt the read
//             let result = Pin::new(&mut self.inner).poll_read(cx, buf);

//             if result.is_ready() {
//                 // Schedule next read
//                 self.next_read = Some(now + self.delay);
//             }

//             result
//         }
//     }

//     #[tokio::test]
//     async fn test_slow_reader() {
//         let secret = [0u8; 32];
//         let request = Request::TcpConnect(secret, Address::Domain("example.com".to_string(), 80));
//         let bytes: Vec<u8> = request.into();

//         // Create a slow reader with 10ms delay per read
//         let cursor = Cursor::new(bytes);
//         let mut slow_reader = RateLimitedReader::new(cursor, Duration::from_millis(10));

//         let parsed_request = Request::read(&mut slow_reader).await.unwrap();

//         match parsed_request {
//             Request::TcpConnect(parsed_secret, Address::Domain(domain, port)) => {
//                 assert_eq!(secret, parsed_secret);
//                 assert_eq!(domain, "example.com");
//                 assert_eq!(port, 80);
//             }
//             _ => panic!("Wrong request type"),
//         }
//     }

//     // Test handling of malformed headers
//     #[tokio::test]
//     async fn test_malformed_headers() {
//         // Test cases for various malformed headers
//         let test_cases = vec![
//             // Length too large for the actual data
//             vec![
//                 0,
//                 0,
//                 1,
//                 0,
//                 Request::RTYP_TCP_CONNECT,
//                 Request::ATYP_DOMAIN,
//                 0,
//                 80,
//             ], // Length 256 but no data
//             // Invalid address type
//             vec![0, 0, 0, 4, Request::RTYP_TCP_CONNECT, 99, 0, 80, 1, 1, 1, 1],
//             // Truncated IPv4 address
//             vec![
//                 0,
//                 0,
//                 0,
//                 4,
//                 Request::RTYP_TCP_CONNECT,
//                 Request::ATYP_IPV4,
//                 0,
//                 80,
//                 127,
//                 0,
//                 0,
//             ], // Missing last byte
//             // Truncated IPv6 address
//             vec![
//                 0,
//                 0,
//                 0,
//                 16,
//                 Request::RTYP_TCP_CONNECT,
//                 Request::ATYP_IPV6,
//                 0,
//                 80,
//             ], // Missing IPv6 bytes
//             // Domain with invalid UTF-8
//             vec![
//                 0,
//                 0,
//                 0,
//                 4,
//                 Request::RTYP_TCP_CONNECT,
//                 Request::ATYP_DOMAIN,
//                 0,
//                 80,
//                 0xFF,
//                 0xFF,
//                 0xFF,
//                 0xFF,
//             ],
//         ];

//         for (i, test_case) in test_cases.iter().enumerate() {
//             let mut cursor = Cursor::new(test_case);
//             let result = Request::read(&mut cursor).await;
//             assert!(
//                 result.is_err(),
//                 "Test case {} should have failed but succeeded: {:?}",
//                 i,
//                 test_case
//             );
//         }
//     }

//     // Test extremely large port numbers
//     #[tokio::test]
//     async fn test_port_boundaries() {
//         let edge_ports = vec![0, 1, 65534, 65535];

//         for port in edge_ports {
//             // Test with domain address
//             let request =
//                 Request::TcpConnect([0u8; 32], Address::Domain("example.com".to_string(), port));
//             let bytes: Vec<u8> = request.clone().into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed = Request::read(&mut cursor).await.unwrap();

//             match parsed {
//                 Request::TcpConnect(_, Address::Domain(_, parsed_port)) => {
//                     assert_eq!(port, parsed_port);
//                 }
//                 _ => panic!("Wrong address type"),
//             }
//         }
//     }

//     // Test various IPv4 subnet addresses
//     #[tokio::test]
//     async fn test_ipv4_subnets() {
//         let subnet_tests = vec![
//             // Class A private network
//             Ipv4Addr::new(10, 0, 0, 1),
//             // Class B private network
//             Ipv4Addr::new(172, 16, 0, 1),
//             // Class C private network
//             Ipv4Addr::new(192, 168, 0, 1),
//             // Loopback
//             Ipv4Addr::new(127, 0, 0, 1),
//             // Link-local
//             Ipv4Addr::new(169, 254, 0, 1),
//             // Multicast
//             Ipv4Addr::new(224, 0, 0, 1),
//         ];

//         for ip in subnet_tests {
//             let addr = SocketAddrV4::new(ip, 80);
//             let request = Request::TcpConnect([0u8; 32], Address::IPv4(addr));
//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed = Request::read(&mut cursor).await.unwrap();

//             match parsed {
//                 Request::TcpConnect(_, Address::IPv4(parsed_addr)) => {
//                     assert_eq!(addr, parsed_addr);
//                 }
//                 _ => panic!("Wrong address type"),
//             }
//         }
//     }

//     // Test various IPv6 special addresses
//     #[tokio::test]
//     async fn test_ipv6_special_addresses() {
//         let special_addrs = vec![
//             // Unspecified
//             Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
//             // Loopback
//             Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
//             // IPv4-mapped IPv6
//             Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201),
//             // Link-local
//             Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
//             // Multicast
//             Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
//         ];

//         for ip in special_addrs {
//             let addr = SocketAddrV6::new(ip, 80, 0, 0);
//             let request = Request::TcpConnect([0u8; 32], Address::IPv6(addr));
//             let bytes: Vec<u8> = request.into();
//             let mut cursor = Cursor::new(bytes);
//             let parsed = Request::read(&mut cursor).await.unwrap();

//             match parsed {
//                 Request::TcpConnect(_, Address::IPv6(parsed_addr)) => {
//                     assert_eq!(addr, parsed_addr);
//                 }
//                 _ => panic!("Wrong address type"),
//             }
//         }
//     }
// }
