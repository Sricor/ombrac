use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use bytes::Bytes;
use ombrac_macros::{debug, error, info, warn};
use tokio::sync::Mutex;

use crate::quic::TransportConfig;
use crate::quic::protocol::{decode_addr, encode_addr};
use crate::quic::stream::Stream;
use crate::{DatagramReceiver, DatagramSender, Initiator, Reliable};

use super::{Result, error::Error};

#[derive(Debug, Clone)]
pub struct Config {
    pub server_name: String,
    pub server_addr: SocketAddr,

    pub enable_zero_rtt: bool,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub skip_server_verification: bool,
    pub root_ca_path: Option<PathBuf>,
    pub client_cert_key_paths: Option<(PathBuf, PathBuf)>,

    transport_config: Arc<quinn::TransportConfig>,
}

impl Config {
    pub fn new(server_addr: SocketAddr, server_name: String) -> Self {
        Self {
            server_name,
            server_addr,
            root_ca_path: None,
            client_cert_key_paths: None,
            skip_server_verification: false,
            enable_zero_rtt: false,
            alpn_protocols: Vec::new(),
            transport_config: Arc::new(quinn::TransportConfig::default()),
        }
    }

    pub fn transport_config(&mut self, config: TransportConfig) {
        self.transport_config = Arc::new(config.0)
    }

    fn build_endpoint_config(&self) -> Result<quinn::EndpointConfig> {
        Ok(quinn::EndpointConfig::default())
    }

    fn build_client_config(&self) -> Result<quinn::ClientConfig> {
        use quinn::crypto::rustls::QuicClientConfig;

        let crypto_config = Arc::new(QuicClientConfig::try_from(self.build_tls_config()?)?);

        let mut client_config = quinn::ClientConfig::new(crypto_config);
        client_config.transport_config(self.transport_config.clone());

        Ok(client_config)
    }

    fn build_tls_config(&self) -> Result<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = &self.root_ca_path {
            let certs = super::load_certificates(path)?;
            roots.add_parsable_certificates(certs);
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let config_builder = rustls::ClientConfig::builder().with_root_certificates(roots);

        let mut tls_config = if let Some((cert_path, key_path)) = &self.client_cert_key_paths {
            let client_certs = super::load_certificates(cert_path)?;
            let client_key = super::load_private_key(key_path)?;
            config_builder.with_client_auth_cert(client_certs, client_key)?
        } else {
            config_builder.with_no_client_auth()
        };

        tls_config.alpn_protocols = self.alpn_protocols.clone();

        if self.skip_server_verification {
            warn!("TLS certificate verification is DISABLED - this is not secure!");
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(cert_verifier::NullVerifier));
        }

        if self.enable_zero_rtt {
            tls_config.enable_early_data = true;
        }

        Ok(tls_config)
    }
}

pub struct Client {
    config: Config,
    endpoint: quinn::Endpoint,
    connection: ArcSwap<quinn::Connection>,
    reconnect_lock: Mutex<()>,
}

impl Client {
    pub async fn new(config: Config, socket: UdpSocket) -> Result<Self> {
        let client_config = config.build_client_config()?;
        let endpoint_config = config.build_endpoint_config()?;

        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("No async runtime found"))?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            runtime.wrap_udp_socket(socket)?,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(config.server_addr, &config.server_name)?
            .await?;

        info!(
            "Initial connection established with {} at {}",
            config.server_addr, &config.server_name
        );

        let connection = ArcSwap::new(Arc::new(connection));

        Ok(Self {
            config,
            endpoint,
            connection,
            reconnect_lock: Mutex::new(()),
        })
    }

    pub async fn open_bidirectional(&self) -> Result<Stream> {
        let conn_arc = self.connection.load();
        match conn_arc.open_bi().await {
            Ok((send, recv)) => Ok(Stream(send, recv)),
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::Reset)
            | Err(quinn::ConnectionError::TimedOut) => {
                warn!("Connection lost, attempting to reconnect");
                let (send, recv) = self.reconnect_and_open_bi(conn_arc).await?;
                Ok(Stream(send, recv))
            }
            Err(e) => {
                error!("Unexpected connection error: {:?}", e);
                Err(Error::QuinnConnection(e))
            }
        }
    }

    pub async fn send_datagram(&self, dest_addr: SocketAddr, payload: &[u8]) -> Result<()> {
        info!(
            "Client Send Datagram, dest_addr: {}, playload: {}",
            dest_addr,
            payload.len()
        );

        let mut datagram_buf = encode_addr(&dest_addr);
        datagram_buf.extend_from_slice(payload);
        let datagram = bytes::Bytes::from(datagram_buf);

        loop {
            let conn_arc = self.connection.load();
            match conn_arc.send_datagram(datagram.clone()) {
                Ok(()) => return Ok(()),
                Err(quinn::SendDatagramError::ConnectionLost(e)) => {
                    warn!("Connection lost on send, attempting to reconnect: {}", e);
                    self.reconnect_on_error(conn_arc).await?;
                }
                Err(e) => {
                    error!("Failed to send datagram: {:?}", e);
                    return Err(Error::QuinnSendDatagram(e));
                }
            }
        }
    }

    pub async fn read_datagram(&self) -> Result<(SocketAddr, Bytes)> {
        loop {
            let conn_arc = self.connection.load();
            match conn_arc.read_datagram().await {
                Ok(datagram) => {
                    if let Some((addr, payload)) = decode_addr(&datagram) {
                        info!(
                            "Client Read Datagram, addr: {}, playload: {}",
                            addr,
                            payload.len()
                        );
                        return Ok((addr, Bytes::copy_from_slice(payload)));
                    } else {
                        warn!("Received invalid datagram from server");
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::ConnectionClosed(_))
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::Reset)
                | Err(quinn::ConnectionError::TimedOut) => {
                    warn!("Connection lost on read, attempting to reconnect");
                    self.reconnect_on_error(conn_arc).await?;
                }
                Err(e) => {
                    error!("Unexpected connection error on read: {:?}", e);
                    return Err(Error::QuinnConnection(e));
                }
            }
        }
    }

    async fn reconnect_on_error(&self, old_conn_arc: Guard<Arc<quinn::Connection>>) -> Result<()> {
        let _lock = self.reconnect_lock.lock().await;
        if !Arc::ptr_eq(&*old_conn_arc, &*self.connection.load()) {
            return Ok(());
        }

        self.connection.store(Arc::new(self.connect().await?));

        Ok(())
    }

    pub async fn reconnect(&self) -> Result<()> {
        let _lock = self.reconnect_lock.lock().await;
        self.connection.store(Arc::new(self.connect().await?));
        Ok(())
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"Client closed");
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    pub async fn wait_idle(&self) -> () {
        self.endpoint.wait_idle().await;
    }

    /// Get the local SocketAddr the underlying socket is bound to
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Switch to a new UDP socket
    pub fn rebind(&self, socket: UdpSocket) -> Result<()> {
        Ok(self.endpoint.rebind(socket)?)
    }

    async fn reconnect_and_open_bi(
        &self,
        old_conn_arc: Guard<Arc<quinn::Connection>>,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let _lock = self.reconnect_lock.lock().await;

        if !Arc::ptr_eq(&*old_conn_arc, &*self.connection.load()) {
            return Ok(self.connection.load().open_bi().await?);
        }
        self.connection.store(Arc::new(self.connect().await?));

        Ok(self.connection.load().open_bi().await?)
    }

    async fn connect(&self) -> Result<quinn::Connection> {
        let connecting = self
            .endpoint
            .connect(self.config.server_addr, &self.config.server_name)?;

        let (connection, _is_zero_rtt_accepted) = if self.config.enable_zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, zero_rtt_accepted)) => {
                    let is_accepted = zero_rtt_accepted.await;
                    if !is_accepted {
                        warn!("Zero-RTT connection not accepted by server");
                    }

                    (conn, is_accepted)
                }
                Err(conn) => {
                    debug!("Zero-RTT not available, using regular connection");
                    (conn.await?, false)
                }
            }
        } else {
            (connecting.await?, false)
        };

        info!(
            "Connection established with {} at {} (0-RTT: {})",
            &self.config.server_name, &self.config.server_addr, _is_zero_rtt_accepted
        );

        Ok(connection)
    }
}

impl Initiator for Client {
    async fn open_bidirectional(&self) -> io::Result<impl Reliable> {
        Ok(Client::open_bidirectional(self).await?)
    }
}

impl DatagramSender for Client {
    async fn send_datagram(&self, dest: SocketAddr, data: &[u8]) -> io::Result<()> {
        Ok(self.send_datagram(dest, data).await?)
    }
}

impl DatagramReceiver for Client {
    async fn read_datagram(&self) -> io::Result<(SocketAddr, bytes::Bytes)> {
        Ok(self.read_datagram().await?)
    }
}

mod cert_verifier {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct NullVerifier;

    impl ServerCertVerifier for NullVerifier {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
                .to_vec()
        }
    }
}
