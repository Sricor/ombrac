use std::path::PathBuf;
use std::{fs, io};

use async_channel::{Receiver, Sender};
use bytes::Bytes;
use ombrac_macros::error;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{Reliable, Result, Transport, Unreliable};

pub mod client;
pub mod server;

pub struct Connection(Receiver<Stream>, Receiver<Datagram>);
pub struct Stream(quinn::SendStream, quinn::RecvStream);
pub struct Datagram(Sender<Bytes>, Receiver<Bytes>);

impl Transport for Connection {
    async fn reliable(&self) -> Result<impl Reliable> {
        match self.0.recv().await {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }

    async fn unreliable(&self) -> Result<impl Unreliable> {
        match self.1.recv().await {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }
}

impl Reliable for Stream {}
impl Unreliable for Datagram {
    async fn recv(&self) -> Result<Bytes> {
        match self.1.recv().await {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }

    async fn send(&self, data: Bytes) -> Result<()> {
        if let Err(e) = self.0.send(data).await {
            return Err(e.into());
        }

        Ok(())
    }
}

impl Connection {
    fn spawn_datagram(conn: quinn::Connection) -> Datagram {
        const DEFAULT_SIZE: usize = 1024;

        let conn_recv = conn.clone();

        let (sender, datagram_to_send) = async_channel::bounded(DEFAULT_SIZE);
        let (forwarder, receiver) = async_channel::bounded(DEFAULT_SIZE);

        tokio::spawn(async move {
            let handle = tokio::spawn(async move {
                while let Ok(datagram) = datagram_to_send.recv().await {
                    if let Err(_error) = conn.send_datagram_wait(datagram).await {
                        error!("{_error}");

                        break;
                    }
                }
            });

            loop {
                match conn_recv.read_datagram().await {
                    Ok(datagram) => {
                        if forwarder.send(datagram).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read datagram from connection: {}", e);
                        break;
                    }
                }
            }

            handle.abort();
        });

        Datagram(sender, receiver)
    }
}

fn load_certificates(path: &PathBuf) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(path)?;

    let result = if path.extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect::<std::result::Result<_, _>>()?
    };

    Ok(result)
}

fn load_private_key(path: &PathBuf) -> io::Result<PrivateKeyDer<'static>> {
    let key = fs::read(path)?;

    let result = if path.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        match rustls_pemfile::private_key(&mut &*key)? {
            Some(value) => value,
            None => return Err(io::Error::other("load private key error")),
        }
    };

    Ok(result)
}

mod impl_tokio_io {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::Stream;

    impl AsyncRead for Stream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.get_mut().1), cx, buf)
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            AsyncWrite::poll_write(Pin::new(&mut self.get_mut().0), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().0), cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().0), cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Reliable, Transport};

    use super::{client, server, Connection};
    use std::{net::SocketAddr, time::Duration};
    use tests_support::cert::CertificateGenerator;
    use tests_support::net::find_available_udp_addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TIMEOUT: Duration = Duration::from_millis(300);
    const STARTUP_WAIT: Duration = Duration::from_millis(300);

    async fn setup_connections(
        listen_addr: SocketAddr,
        zero_rtt: bool,
        enable_multiplexing: bool,
    ) -> (Connection, Connection) {
        tokio::time::sleep(STARTUP_WAIT).await;

        let addr_str = listen_addr.to_string();
        let (cert_path, key_path) = CertificateGenerator::generate();

        let server_conn = server::Builder::new(addr_str.clone())
            .with_tls_cert(cert_path.clone())
            .with_tls_key(key_path.clone())
            .with_enable_zero_rtt(zero_rtt)
            .build()
            .await
            .expect("Failed to build server connection");

        tokio::time::sleep(STARTUP_WAIT).await;

        let client_conn = client::Builder::new(addr_str)
            .with_server_name("localhost".to_string())
            .with_tls_cert(cert_path.clone())
            .with_enable_zero_rtt(zero_rtt)
            .with_enable_connection_multiplexing(enable_multiplexing)
            .build()
            .await
            .expect("Failed to build client connection");

        (server_conn, client_conn)
    }

    async fn fetch_stream(conn: &Connection) -> impl Reliable + '_ {
        tokio::time::timeout(TIMEOUT, conn.reliable())
            .await
            .expect("Timed out waiting for stream")
            .expect("Failed to fetch stream")
    }

    #[tokio::test]
    async fn test_client_server_connection() {
        let listen_addr = find_available_udp_addr("127.0.0.1".parse().unwrap());
        let (server_conn, client_conn) = setup_connections(listen_addr, false, false).await;

        let mut client_stream = fetch_stream(&client_conn).await;
        let msg = b"hello quic";
        client_stream.write_all(msg).await.unwrap();

        let mut server_stream = fetch_stream(&server_conn).await;
        let mut buf = vec![0u8; msg.len()];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn test_client_server_connection_zerortt() {
        let listen_addr = find_available_udp_addr("127.0.0.1".parse().unwrap());
        let (server_conn, client_conn) = setup_connections(listen_addr, true, false).await;

        let mut client_stream = fetch_stream(&client_conn).await;
        let msg = b"hello zerortt";
        client_stream.write_all(msg).await.unwrap();

        let mut server_stream = fetch_stream(&server_conn).await;
        let mut buf = vec![0u8; msg.len()];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn test_multiplexed_streams() {
        let listen_addr = find_available_udp_addr("127.0.0.1".parse().unwrap());
        let (server_conn, client_conn) = setup_connections(listen_addr, false, true).await;

        let mut client_stream1 = fetch_stream(&client_conn).await;
        let msg1 = b"stream 1";
        client_stream1.write_all(msg1).await.unwrap();

        let mut server_stream1 = fetch_stream(&server_conn).await;
        let mut buf1 = vec![0u8; msg1.len()];
        server_stream1.read_exact(&mut buf1).await.unwrap();
        assert_eq!(&buf1, msg1);

        let mut client_stream2 = fetch_stream(&client_conn).await;
        let msg2 = b"stream 2";
        client_stream2.write_all(msg2).await.unwrap();

        let mut server_stream2 = fetch_stream(&server_conn).await;
        let mut buf2 = vec![0u8; msg2.len()];
        server_stream2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, msg2);
    }

    #[tokio::test]
    async fn test_bidirectional_data_exchange() {
        let listen_addr = find_available_udp_addr("127.0.0.1".parse().unwrap());
        let (server_conn, client_conn) = setup_connections(listen_addr, false, false).await;

        let mut client_stream = fetch_stream(&client_conn).await;
        let client_msg = b"hello from client";
        client_stream.write_all(client_msg).await.unwrap();

        let mut server_stream = fetch_stream(&server_conn).await;
        let mut server_buf = vec![0u8; client_msg.len()];
        server_stream.read_exact(&mut server_buf).await.unwrap();
        assert_eq!(&server_buf, client_msg);

        let server_reply = b"hello from server";
        server_stream.write_all(server_reply).await.unwrap();
        let mut client_buf = vec![0u8; server_reply.len()];
        client_stream.read_exact(&mut client_buf).await.unwrap();
        assert_eq!(&client_buf, server_reply);
    }

    mod tests_datagram {
        use bytes::Bytes;

        use crate::{Transport, Unreliable};

        use super::{find_available_udp_addr, setup_connections};

        #[tokio::test]
        async fn test_bidirectional_data_exchange() {
            let listen_addr = find_available_udp_addr("127.0.0.1".parse().unwrap());
            let (server_conn, client_conn) = setup_connections(listen_addr, false, false).await;
            let client_datagram = client_conn.unreliable().await.unwrap();
            let client_msg = b"hello from client".to_vec();

            client_datagram
                .send(Bytes::from(client_msg.clone()))
                .await
                .unwrap();

            let server_datagram = server_conn.unreliable().await.unwrap();
            let server_msg = server_datagram.recv().await.unwrap();

            assert_eq!(client_msg, server_msg);
        }
    }
}
