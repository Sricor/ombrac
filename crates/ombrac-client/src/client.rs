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

    pub async fn udp_associate(&self) -> io::Result<Datagram<impl Unreliable + '_>> {
        let stream = self.unreliable().await?;

        Ok(Datagram::with(self.secret, stream))
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


pub struct Datagram<U: Unreliable>(Secret, U);

impl<U: Unreliable> Datagram<U> {
    fn with(secret: Secret, stream: U) -> Self {
        Self(secret, stream)
    }

    pub async fn send<A, B>(&self, addr: A, data: B) -> io::Result<()>
    where
        A: Into<Address>,
        B: Into<Bytes>,
    {
        let packet = Packet::with(self.0, addr, data).to_bytes()?;

        if let Err(error) = self.1.send(packet).await {
            return Err(io::Error::other(error.to_string()));
        };

        Ok(())
    }

    pub async fn recv(&self) -> io::Result<(Address, Bytes)> {
        match self.1.recv().await {
            Ok(mut data) => {
                let packet = Packet::from_bytes(&mut data)?;
                Ok((packet.address, packet.data))
            }
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }
}
