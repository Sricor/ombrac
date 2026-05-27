use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use ombrac::protocol::Address as OmbracAddress;
use ombrac_macros::warn;

use super::{ArcClient, forward_tcp};

const VER: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;

const REP_GRANTED: u8 = 0x5A;
const REP_REJECTED: u8 = 0x5B;

/// Hard cap on USERID / domain length to avoid resource exhaustion when a
/// peer sends a stream with no NUL terminator. 255 bytes is well above any
/// real-world value.
const MAX_NUL_FIELD: usize = 255;

/// Top-level SOCKS4 connection handler used by the accept loop.
pub async fn handle(stream: TcpStream, peer: SocketAddr, client: ArcClient) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut stream = stream;
    let addr = match parse_request(&mut stream).await {
        Ok(a) => a,
        Err(err) => {
            // Best-effort rejection reply, then propagate.
            let _ = write_reply(&mut stream, REP_REJECTED).await;
            return Err(err);
        }
    };

    let dst_display = addr_display(&addr);

    let mut dest = match client.open_bidirectional(addr).await {
        Ok(s) => s,
        Err(err) => {
            let _ = write_reply(&mut stream, REP_REJECTED).await;
            return Err(err);
        }
    };

    write_reply(&mut stream, REP_GRANTED).await?;
    forward_tcp(&mut stream, &mut dest, peer, &dst_display).await
}

/// Parses a SOCKS4 / SOCKS4a CONNECT request from the stream and returns the
/// destination address.
async fn parse_request<S>(stream: &mut S) -> io::Result<OmbracAddress>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 8];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks version {:#x}", head[0]),
        ));
    }
    if head[1] != CMD_CONNECT {
        warn!(cmd = head[1], "unsupported socks4 command (only CONNECT is supported)");
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported socks4 command {:#x}", head[1]),
        ));
    }
    let port = u16::from_be_bytes([head[2], head[3]]);
    let ip = [head[4], head[5], head[6], head[7]];

    // USERID — read until NUL, discard.
    read_nul_terminated(stream).await?;

    // SOCKS4a indicator: 0.0.0.X where X != 0.
    if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let domain = read_nul_terminated(stream).await?;
        if domain.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty domain in socks4a request",
            ));
        }
        Ok(OmbracAddress::Domain(Bytes::from(domain), port))
    } else {
        let ipv4 = Ipv4Addr::from(ip);
        Ok(OmbracAddress::SocketV4(SocketAddrV4::new(ipv4, port)))
    }
}

async fn read_nul_terminated<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let b = stream.read_u8().await?;
        if b == 0 {
            return Ok(out);
        }
        out.push(b);
        if out.len() > MAX_NUL_FIELD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks4 field exceeded maximum length",
            ));
        }
    }
}

async fn write_reply<S>(stream: &mut S, code: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    // VN=0, CD=code, DSTPORT=0, DSTIP=0.0.0.0 — fields are informational.
    stream
        .write_all(&[0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
}

fn addr_display(addr: &OmbracAddress) -> String {
    match addr {
        OmbracAddress::SocketV4(a) => a.to_string(),
        OmbracAddress::SocketV6(a) => a.to_string(),
        OmbracAddress::Domain(d, p) => match std::str::from_utf8(d) {
            Ok(s) => format!("{}:{}", s, p),
            Err(_) => format!("<invalid-domain>:{}", p),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn parses_ipv4_connect_with_empty_userid() {
        let (mut client, mut server) = duplex(64);
        // VER=4, CMD=1, PORT=443, IP=1.2.3.4, USERID=""
        let mut buf = vec![0x04, 0x01, 0x01, 0xBB, 1, 2, 3, 4];
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let addr = parse_request(&mut server).await.unwrap();
        match addr {
            OmbracAddress::SocketV4(a) => {
                assert_eq!(a.ip().octets(), [1, 2, 3, 4]);
                assert_eq!(a.port(), 443);
            }
            _ => panic!("expected v4"),
        }
    }

    #[tokio::test]
    async fn parses_ipv4_connect_with_userid_discarded() {
        let (mut client, mut server) = duplex(64);
        let mut buf = vec![0x04, 0x01, 0x00, 0x50, 93, 184, 216, 34];
        buf.extend_from_slice(b"alice");
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let addr = parse_request(&mut server).await.unwrap();
        match addr {
            OmbracAddress::SocketV4(a) => {
                assert_eq!(a.ip().octets(), [93, 184, 216, 34]);
                assert_eq!(a.port(), 80);
            }
            _ => panic!("expected v4"),
        }
    }

    #[tokio::test]
    async fn parses_socks4a_domain() {
        let (mut client, mut server) = duplex(128);
        let mut buf = vec![0x04, 0x01, 0x01, 0xBB, 0, 0, 0, 7]; // 0.0.0.7 → SOCKS4a
        buf.extend_from_slice(b"user"); // USERID
        buf.push(0x00);
        buf.extend_from_slice(b"example.com");
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let addr = parse_request(&mut server).await.unwrap();
        match addr {
            OmbracAddress::Domain(d, p) => {
                assert_eq!(&d[..], b"example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
    }

    #[tokio::test]
    async fn rejects_bind_command() {
        let (mut client, mut server) = duplex(64);
        let mut buf = vec![0x04, 0x02, 0x00, 0x50, 1, 2, 3, 4];
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let res = parse_request(&mut server).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn rejects_unknown_version() {
        let (mut client, mut server) = duplex(64);
        let mut buf = vec![0x05, 0x01, 0x00, 0x50, 1, 2, 3, 4];
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let res = parse_request(&mut server).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn rejects_overlong_userid() {
        let (mut client, mut server) = duplex(1024);
        let mut buf = vec![0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4];
        buf.extend(std::iter::repeat(b'a').take(MAX_NUL_FIELD + 1));
        buf.push(0x00);
        client.write_all(&buf).await.unwrap();
        let res = parse_request(&mut server).await;
        assert!(res.is_err());
    }
}
