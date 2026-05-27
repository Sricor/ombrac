use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use ombrac::protocol::Address as OmbracAddress;
use ombrac_macros::{info, warn};

use super::{ArcClient, forward_tcp};

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
#[cfg(feature = "datagram")]
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Top-level SOCKS5 connection handler used by the accept loop.
pub async fn handle(stream: TcpStream, peer: SocketAddr, client: ArcClient) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut stream = stream;

    method_selection(&mut stream).await?;
    let request = read_request(&mut stream).await?;

    match request.cmd {
        CMD_CONNECT => handle_connect(&mut stream, peer, &client, request.addr).await,
        #[cfg(feature = "datagram")]
        CMD_UDP_ASSOCIATE => handle_associate(&mut stream, peer, &client).await,
        _ => {
            warn!(src_addr = %peer, cmd = request.cmd, "unsupported socks5 command");
            write_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED, &SocksAddr::unspecified()).await?;
            Ok(())
        }
    }
}

async fn method_selection<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks version {:#x}", head[0]),
        ));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream.write_all(&[VER, METHOD_NO_ACCEPTABLE]).await?;
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no acceptable authentication method",
        ))
    }
}

struct Request {
    cmd: u8,
    addr: SocksAddr,
}

async fn read_request<S>(stream: &mut S) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks version {:#x}", head[0]),
        ));
    }
    // head[2] is RSV (must be 0x00 but we don't enforce strictly)
    let cmd = head[1];
    let atyp = head[3];
    let addr = match read_socks_addr(stream, atyp).await {
        Ok(a) => a,
        Err(err) => {
            if err.kind() == io::ErrorKind::Unsupported {
                write_reply(stream, REP_ADDR_TYPE_NOT_SUPPORTED, &SocksAddr::unspecified())
                    .await?;
            }
            return Err(err);
        }
    };
    Ok(Request { cmd, addr })
}

async fn handle_connect<S>(
    stream: &mut S,
    peer: SocketAddr,
    client: &ArcClient,
    addr: SocksAddr,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dst_display = addr.to_string();
    let ombrac_addr = addr.to_ombrac();

    let mut dest = match client.open_bidirectional(ombrac_addr).await {
        Ok(s) => s,
        Err(err) => {
            let rep = io_kind_to_rep(err.kind());
            let _ = write_reply(stream, rep, &SocksAddr::unspecified()).await;
            return Err(err);
        }
    };

    // Echo the requested address as BND.ADDR/BND.PORT for simplicity.
    write_reply(stream, REP_SUCCESS, &addr).await?;

    forward_tcp(stream, &mut dest, peer, &dst_display).await
}

fn io_kind_to_rep(kind: io::ErrorKind) -> u8 {
    match kind {
        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        io::ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        io::ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        io::ErrorKind::TimedOut => REP_TTL_EXPIRED,
        _ => REP_GENERAL_FAILURE,
    }
}

async fn write_reply<S>(stream: &mut S, rep: u8, bnd: &SocksAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(32);
    buf.extend_from_slice(&[VER, rep, 0x00]);
    bnd.encode(&mut buf);
    stream.write_all(&buf).await
}

// ----- UDP ASSOCIATE -----

#[cfg(feature = "datagram")]
async fn handle_associate<S>(
    stream: &mut S,
    peer: SocketAddr,
    client: &ArcClient,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::net::UdpSocket;

    info!(src_addr = %peer, "udp associate started");

    let mut udp_session = client.open_associate();

    let relay_socket = UdpSocket::bind("0.0.0.0:0").await?;
    // Use peer's local-side IP as the advertised relay IP. Fall back to the
    // socket's own local_addr if we can't read the stream's local side.
    let relay_port = relay_socket.local_addr()?.port();
    let relay_ip = local_ip_for_peer(peer);
    let relay_addr = SocketAddr::new(relay_ip, relay_port);
    info!(relay_addr = %relay_addr, "udp relay listening");

    let bnd = SocksAddr::from_socket(relay_addr);
    write_reply(stream, REP_SUCCESS, &bnd).await?;

    let mut client_src: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            biased;
            r = stream.read_u8() => {
                match r {
                    Ok(0) | Err(_) => {
                        info!(src_addr = %peer, "tcp control connection closed, ending udp session");
                        return Ok(());
                    }
                    _ => {}
                }
            }

            Some((data, from_addr)) = udp_session.recv_from() => {
                if let Some(dest) = client_src {
                    let socks_from = SocksAddr::from_ombrac(from_addr)?;
                    let packet = encode_udp_packet(&socks_from, &data);
                    relay_socket.send_to(&packet, dest).await?;
                } else {
                    warn!("received packet from tunnel before client, discarding packet");
                }
            }

            r = relay_socket.recv_from(&mut buf) => {
                let (len, src) = r?;
                if client_src.is_none() {
                    client_src = Some(src);
                    info!(client_addr = %src, "first udp packet received from client");
                }
                let (dest_addr, payload) = match decode_udp_packet(&buf[..len]) {
                    Some(v) => v,
                    None => {
                        warn!("malformed udp packet from client, discarding");
                        continue;
                    }
                };
                udp_session.send_to(payload, dest_addr.to_ombrac()).await?;
            }
        }
    }
}

#[cfg(feature = "datagram")]
fn local_ip_for_peer(peer: SocketAddr) -> std::net::IpAddr {
    match peer {
        SocketAddr::V4(_) => std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// SOCKS5 UDP request:
///   RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
#[cfg(feature = "datagram")]
fn decode_udp_packet(buf: &[u8]) -> Option<(SocksAddr, Bytes)> {
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 0 {
        return None;
    }
    if buf[2] != 0 {
        // FRAG not supported
        return None;
    }
    let atyp = buf[3];
    let (addr, header_len) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < 4 + 4 + 2 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (SocksAddr::V4(SocketAddrV4::new(ip, port)), 10)
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                return None;
            }
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return None;
            }
            let domain = buf[5..5 + len].to_vec();
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            (SocksAddr::Domain(domain, port), 5 + len + 2)
        }
        ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (SocksAddr::V6(SocketAddrV6::new(ip, port, 0, 0)), 22)
        }
        _ => return None,
    };
    let data = Bytes::copy_from_slice(&buf[header_len..]);
    Some((addr, data))
}

#[cfg(feature = "datagram")]
fn encode_udp_packet(addr: &SocksAddr, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(data.len() + 32);
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
    addr.encode(&mut buf);
    buf.extend_from_slice(data);
    buf.freeze()
}

// ----- Address encoding -----

/// SOCKS5 address representation. Decoupled from `ombrac::protocol::Address`
/// so we can carry IP variants without losing information when echoing back
/// in BND fields.
pub enum SocksAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(Vec<u8>, u16),
}

impl SocksAddr {
    fn unspecified() -> Self {
        SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    #[cfg(feature = "datagram")]
    fn from_socket(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => SocksAddr::V4(a),
            SocketAddr::V6(a) => SocksAddr::V6(a),
        }
    }

    fn to_ombrac(&self) -> OmbracAddress {
        match self {
            SocksAddr::V4(a) => OmbracAddress::SocketV4(*a),
            SocksAddr::V6(a) => OmbracAddress::SocketV6(*a),
            SocksAddr::Domain(d, p) => OmbracAddress::Domain(Bytes::copy_from_slice(d), *p),
        }
    }

    #[cfg(feature = "datagram")]
    fn from_ombrac(addr: OmbracAddress) -> io::Result<Self> {
        Ok(match addr {
            OmbracAddress::SocketV4(a) => SocksAddr::V4(a),
            OmbracAddress::SocketV6(a) => SocksAddr::V6(a),
            OmbracAddress::Domain(d, p) => {
                if d.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "domain name too long for socks5",
                    ));
                }
                SocksAddr::Domain(d.to_vec(), p)
            }
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            SocksAddr::V4(a) => {
                buf.extend_from_slice(&[ATYP_IPV4]);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
            SocksAddr::V6(a) => {
                buf.extend_from_slice(&[ATYP_IPV6]);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
            SocksAddr::Domain(d, p) => {
                buf.extend_from_slice(&[ATYP_DOMAIN, d.len() as u8]);
                buf.extend_from_slice(d);
                buf.extend_from_slice(&p.to_be_bytes());
            }
        }
    }
}

impl std::fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksAddr::V4(a) => write!(f, "{}", a),
            SocksAddr::V6(a) => write!(f, "{}", a),
            SocksAddr::Domain(d, p) => match std::str::from_utf8(d) {
                Ok(s) => write!(f, "{}:{}", s, p),
                Err(_) => write!(f, "<invalid-domain>:{}", p),
            },
        }
    }
}

async fn read_socks_addr<S>(stream: &mut S, atyp: u8) -> io::Result<SocksAddr>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(SocksAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty domain name",
                ));
            }
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            Ok(SocksAddr::Domain(domain, port))
        }
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported atyp {:#x}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn method_selection_no_auth() {
        let (mut client, mut server) = duplex(64);
        // client sends VER NMETHODS METHODS
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        method_selection(&mut server).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn method_selection_rejects_when_no_auth_missing() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let res = method_selection(&mut server).await;
        assert!(res.is_err());
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn request_parses_ipv4_connect() {
        let (mut client, mut server) = duplex(64);
        // VER CMD RSV ATYP=1 IP(4) PORT(2)
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
            .await
            .unwrap();
        let req = read_request(&mut server).await.unwrap();
        assert_eq!(req.cmd, 0x01);
        match req.addr {
            SocksAddr::V4(a) => {
                assert_eq!(a.ip().octets(), [1, 2, 3, 4]);
                assert_eq!(a.port(), 443);
            }
            _ => panic!("expected v4"),
        }
    }

    #[tokio::test]
    async fn request_parses_domain_connect() {
        let (mut client, mut server) = duplex(64);
        let domain = b"example.com";
        let mut bytes = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&bytes).await.unwrap();
        let req = read_request(&mut server).await.unwrap();
        assert_eq!(req.cmd, 0x01);
        match req.addr {
            SocksAddr::Domain(d, p) => {
                assert_eq!(d, domain);
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
    }

    #[tokio::test]
    async fn request_parses_ipv6_connect() {
        let (mut client, mut server) = duplex(64);
        let mut bytes = vec![0x05, 0x01, 0x00, 0x04];
        let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        bytes.extend_from_slice(&ip);
        bytes.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&bytes).await.unwrap();
        let req = read_request(&mut server).await.unwrap();
        match req.addr {
            SocksAddr::V6(a) => {
                assert_eq!(a.port(), 80);
                assert_eq!(a.ip(), &Ipv6Addr::LOCALHOST);
            }
            _ => panic!("expected v6"),
        }
    }

    #[tokio::test]
    async fn request_unsupported_atyp_writes_reply() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x05, 0x01, 0x00, 0x09]).await.unwrap();
        let res = read_request(&mut server).await;
        assert!(res.is_err());
        // Drain the error reply (10 bytes: VER REP RSV ATYP=1 IP=4 PORT=2)
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], REP_ADDR_TYPE_NOT_SUPPORTED);
    }

    #[cfg(feature = "datagram")]
    #[test]
    fn udp_packet_roundtrip_ipv4() {
        let addr = SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));
        let data = b"hello world";
        let packet = encode_udp_packet(&addr, data);
        let (decoded_addr, payload) = decode_udp_packet(&packet).unwrap();
        assert_eq!(payload.as_ref(), data);
        match decoded_addr {
            SocksAddr::V4(a) => {
                assert_eq!(a.ip().octets(), [1, 1, 1, 1]);
                assert_eq!(a.port(), 53);
            }
            _ => panic!("expected v4"),
        }
    }

    #[cfg(feature = "datagram")]
    #[test]
    fn udp_packet_roundtrip_domain() {
        let addr = SocksAddr::Domain(b"example.com".to_vec(), 443);
        let data = b"payload";
        let packet = encode_udp_packet(&addr, data);
        let (decoded_addr, payload) = decode_udp_packet(&packet).unwrap();
        assert_eq!(payload.as_ref(), data);
        match decoded_addr {
            SocksAddr::Domain(d, p) => {
                assert_eq!(d, b"example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
    }

    #[cfg(feature = "datagram")]
    #[test]
    fn udp_packet_rejects_fragmented() {
        let mut buf = vec![0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 53];
        buf.extend_from_slice(b"data");
        assert!(decode_udp_packet(&buf).is_none());
    }
}
