use std::io;

use bytes::Bytes;
use ombrac::prelude::*;
use ombrac_transport::{Reliable, Transport, Unreliable};

pub struct Client<T> {
    secret: Secret,
    transport: T,
}

impl<T: Transport> Client<T> {
    pub fn new(secret: Secret, transport: T) -> Self {
        Self { secret, transport }
    }

    pub async fn tcp_connect<R, A>(&self, stream: &mut R, addr: A) -> io::Result<()>
    where
        R: Reliable,
        A: Into<Address>,
    {
        use tokio::io::AsyncWriteExt;

        let request = Connect::with(self.secret, addr).to_bytes()?;

        stream.write_all(&request).await?;

        Ok(())
    }

    pub async fn udp_associate<U, A, B>(&self, stream: &U, addr: A, data: B) -> io::Result<()>
    where
        U: Unreliable,
        A: Into<Address>,
        B: Into<Bytes>,
    {
        let request = Packet::with(self.secret, addr, data).to_bytes()?;

        if let Err(error) = stream.send(request).await {
            return Err(io::Error::other(error.to_string()));
        };

        Ok(())
    }

    pub async fn reliable(&self) -> io::Result<impl Reliable + '_> {
        match self.transport.reliable().await {
            Ok(stream) => Ok(stream),
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }

    pub async fn unreliable(&self) -> io::Result<impl Unreliable + '_> {
        match self.transport.unreliable().await {
            Ok(stream) => Ok(stream),
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }
}
