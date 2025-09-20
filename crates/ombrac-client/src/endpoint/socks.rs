use std::sync::Arc;

use ombrac::Secret;
use ombrac::client::Client;
use ombrac_macros::{debug, info};
use ombrac_transport::Initiator;
use socks_lib::io::{self, AsyncRead, AsyncWrite};
use socks_lib::v5::server::Handler;
use socks_lib::v5::{Address as SocksAddress, Request, Stream};

pub struct CommandHandler<I: Initiator> {
    ombrac_client: Arc<Client<I>>,
    secret: Secret,
}

impl<I: Initiator> CommandHandler<I> {
    pub fn new(inner: Arc<Client<I>>, secret: Secret) -> Self {
        Self {
            ombrac_client: inner,
            secret,
        }
    }

    async fn handle_connect(
        &self,
        address: SocksAddress,
        stream: &mut Stream<impl AsyncRead + AsyncWrite + Unpin>,
    ) -> io::Result<(u64, u64)> {
        let addr = util::socks_to_ombrac_addr(address)?;
        let mut outbound = self.ombrac_client.connect(addr, self.secret).await?;
        ombrac::io::util::copy_bidirectional(stream, &mut outbound).await
    }
}

impl<I: Initiator> Handler for CommandHandler<I> {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
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
    use std::io;

    use ombrac::address::{Address as OmbracAddress, Domain as OmbracDoamin};
    use socks_lib::v5::Address as Socks5Address;

    #[inline]
    pub(super) fn socks_to_ombrac_addr(addr: Socks5Address) -> io::Result<OmbracAddress> {
        let result = match addr {
            Socks5Address::IPv4(value) => OmbracAddress::IPv4(value),
            Socks5Address::IPv6(value) => OmbracAddress::IPv6(value),
            Socks5Address::Domain(domain, port) => OmbracAddress::Domain(
                OmbracDoamin::from_bytes(domain.as_bytes().to_owned())?,
                port,
            ),
        };

        Ok(result)
    }
}
