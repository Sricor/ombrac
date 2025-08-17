#[cfg(feature = "datagram")]
mod datagram;
mod error;
mod stream;

pub mod client;
pub mod server;

use std::path::Path;
use std::str::FromStr;
use std::{fs, io};

#[cfg(feature = "datagram")]
use async_channel::Receiver;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;

use crate::Acceptor;
#[cfg(feature = "datagram")]
use crate::quic::datagram::Datagram;
use crate::quic::stream::Stream;

type Result<T> = std::result::Result<T, error::Error>;

#[derive(Debug, Clone, Copy)]
pub enum Congestion {
    Bbr,
    Cubic,
    NewReno,
}

impl FromStr for Congestion {
    type Err = error::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.to_lowercase().as_str() {
            "bbr" => Ok(Congestion::Bbr),
            "cubic" => Ok(Congestion::Cubic),
            "newreno" => Ok(Congestion::NewReno),
            _ => Err(Self::Err::InvalidCongestion),
        }
    }
}

fn load_certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let content = fs::read(path)?;
    let certs = if path.extension().is_some_and(|ext| ext == "der") {
        vec![CertificateDer::from(content)]
    } else {
        rustls_pemfile::certs(&mut &*content).collect::<io::Result<Vec<_>>>()?
    };
    Ok(certs)
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let content = fs::read(path)?;
    let key = if path.extension().is_some_and(|ext| ext == "der") {
        PrivateKeyDer::Pkcs8(content.into())
    } else {
        rustls_pemfile::private_key(&mut &*content)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no private key found in PEM file")
        })?
    };
    Ok(key)
}

pub struct Connection {
    handle: JoinHandle<()>,
    #[cfg(feature = "datagram")]
    datagram: Receiver<Datagram>,
    stream: Receiver<Stream>,
}

impl Acceptor for Connection {
    async fn accept_bidirectional(&self) -> io::Result<impl crate::Reliable> {
        self.stream
            .recv()
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    #[cfg(feature = "datagram")]
    async fn accept_datagram(&self) -> io::Result<impl crate::Unreliable> {
        self.datagram
            .recv()
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
