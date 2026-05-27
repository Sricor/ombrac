use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use ombrac_macros::{error, info};
use ombrac_transport::quic::Connection as QuicConnection;
use ombrac_transport::quic::client::Client as QuicClient;

use crate::client::Client;
use crate::connection::BufferedStream;

#[cfg(feature = "endpoint-socks4")]
pub mod v4;
#[cfg(feature = "endpoint-socks")]
pub mod v5;

pub type ArcClient = Arc<Client<QuicClient, QuicConnection>>;

/// Type alias for SOCKS connection handler functions used by `accept_loop`.
pub type HandlerFn = fn(
    tokio::net::TcpStream,
    SocketAddr,
    ArcClient,
) -> std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// Generic accept loop for both SOCKS4 and SOCKS5 endpoints.
///
/// Accepts incoming TCP connections and spawns a task per connection that
/// invokes `handler` with the stream, the peer address, and a clone of the
/// shared `Client`.
pub async fn accept_loop(
    listener: TcpListener,
    client: ArcClient,
    shutdown_signal: impl Future<Output = ()>,
    handler: HandlerFn,
) -> io::Result<()> {
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_signal => {
                return Ok(());
            }
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(v) => v,
                    Err(_e) => {
                        error!(error = %_e, "failed to accept connection");
                        continue;
                    }
                };
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(_e) = handler(stream, peer, client).await {
                        if !is_benign_io_error(&_e) {
                            error!(src_addr = %peer, error = %_e, "socks connection failed");
                        }
                    }
                });
            }
        }
    }
}

/// Forwards bytes between the SOCKS client stream and the tunnel stream until
/// either side closes. Emits the same tracing fields the previous socks-lib
/// based implementation produced.
#[allow(unused_variables)]
pub async fn forward_tcp<S>(
    stream: &mut S,
    dest: &mut BufferedStream<<QuicConnection as ombrac_transport::Connection>::Stream>,
    src_addr: SocketAddr,
    dst_addr: &str,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match ombrac_transport::io::copy_bidirectional(stream, dest).await {
        Ok(_stats) => {
            info!(
                src_addr = %src_addr,
                dst_addr = %dst_addr,
                send = _stats.a_to_b_bytes,
                recv = _stats.b_to_a_bytes,
                "tcp connect"
            );
            Ok(())
        }
        Err((err, _stats)) => {
            error!(
                src_addr = %src_addr,
                dst_addr = %dst_addr,
                send = _stats.a_to_b_bytes,
                recv = _stats.b_to_a_bytes,
                error = %err,
                "tcp connect"
            );
            Err(err)
        }
    }
}

fn is_benign_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionAborted
    )
}
