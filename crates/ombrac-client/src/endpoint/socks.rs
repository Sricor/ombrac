use std::sync::Arc;

use socks_lib::io::{self, AsyncRead, AsyncWrite};
use socks_lib::v5::server::Handler;
use socks_lib::v5::{Request, Stream};

use ombrac_macros::{debug, info};
use ombrac_transport::{Connection, Initiator};

use crate::client::Client;

pub struct CommandHandler<T, C> {
    client: Arc<Client<T, C>>,
}

impl<T, C> CommandHandler<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    pub fn new(client: Arc<Client<T, C>>) -> Self {
        Self { client }
    }

    async fn handle_connect(
        &self,
        address: socks_lib::v5::Address,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<(u64, u64)> {
        let addr = util::socks_to_ombrac_addr(address)?;
        let mut outbound = self.client.open_bidirectional(addr).await?;
        tokio::io::copy_bidirectional(stream, &mut outbound).await
    }
}

impl<T, C> Handler for CommandHandler<T, C>
where
    T: Initiator<Connection = C>,
    C: Connection,
{
    async fn handle<S>(&self, stream: &mut Stream<S>, request: Request) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!("SOCKS Request: {:?}", request);

        match &request {
            Request::Connect(address) => {
                stream.write_response_unspecified().await?;

                match self.handle_connect(address.clone(), stream).await {
                    Ok(_copy) => {
                        info!(
                            "{} Connect {}, Send: {}, Recv: {}",
                            stream.peer_addr(),
                            address,
                            _copy.0,
                            _copy.1
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
            _ => {
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

mod util {
    use ombrac::protocol::Address as OmbracAddress;

    use std::io;

    use socks_lib::v5::Address as Socks5Address;

    #[inline]
    pub(super) fn socks_to_ombrac_addr(addr: Socks5Address) -> io::Result<OmbracAddress> {
        let result = match addr {
            Socks5Address::IPv4(value) => OmbracAddress::SocketV4(value),
            Socks5Address::IPv6(value) => OmbracAddress::SocketV6(value),
            Socks5Address::Domain(domain, port) => {
                OmbracAddress::Domain(domain.as_bytes().to_owned(), port)
            }
        };

        Ok(result)
    }
}
