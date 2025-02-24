mod v5;

use std::net::SocketAddr;
use std::sync::Arc;
use std::{error::Error, io::Cursor};

use ombrac::prelude::*;
use ombrac_macros::{info, try_or_return};
use ombrac_transport::{Transport, Unreliable};
use socks_lib::socks5::Address as Socks5Address;
use socks_lib::{socks5::UdpPacket, Streamable};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::Client;

pub struct Server {}

pub enum Request {
    TcpConnect(TcpStream, Address),
    UdpAssociate(TcpStream, UdpSocket),
}

impl Server {
    pub async fn listen<T>(addr: SocketAddr, ombrac: Client<T>) -> Result<(), Box<dyn Error>>
    where
        T: Transport + Send + Sync + 'static,
    {
        use ombrac::io::util::copy_bidirectional;

        let ombrac = Arc::new(ombrac);
        let listener = TcpListener::bind(addr).await?;

        info!("SOCKS server listening on {}", listener.local_addr()?);

        while let Ok((stream, _addr)) = listener.accept().await {
            let ombrac = ombrac.clone();

            tokio::spawn(async move {
                let request = try_or_return!(Self::handler_v5(stream).await);

                match request {
                    Request::TcpConnect(mut inbound, addr) => {
                        // TODO: Timeout check
                        let mut outbound = try_or_return!(ombrac.reliable().await);
                        try_or_return!(ombrac.tcp_connect(&mut outbound, addr.clone()).await);

                        let _bytes =
                            try_or_return!(copy_bidirectional(&mut inbound, &mut outbound).await);

                        info!(
                            "TCP Connect {:?} Send {}, Receive {}",
                            addr, _bytes.0, _bytes.1
                        );
                    }
                    Request::UdpAssociate(stream, socket) => {
                        info!("Udp Associate");

                        let unr = ombrac.unreliable().await.unwrap();

                        let socks_1 = Arc::new(socket);
                        let socks_2 = socks_1.clone();
                        let stream_1 = Arc::new(unr);
                        let stream_2 = stream_1.clone();

                        tokio::spawn(async move {
                            while let Ok(mut packet) = stream_1.recv().await {
                                let packet = Packet::from_bytes(&mut packet).unwrap();

                                let target = packet.address.to_socket_addr().await.unwrap();
                                socks_1.send_to(&packet.data, target).await.unwrap();
                            }
                        });

                        let mut buf = [0u8; 2048];

                        loop {
                            let (len, _addr) = socks_2.recv_from(&mut buf).await.unwrap();
                            let data = buf[..len].to_vec();
                            let socks_packet =
                                UdpPacket::read(&mut Cursor::new(data)).await.unwrap();

                            let addr = match socks_packet.address {
                                Socks5Address::Domain(domain, port) => {
                                    Address::Domain(domain, port)
                                }
                                Socks5Address::IPv4(addr) => Address::IPv4(addr),
                                Socks5Address::IPv6(addr) => Address::IPv6(addr),
                            };
                            let data = socks_packet.data;

                            ombrac
                                .udp_associate(stream_2.clone().as_ref(), addr, data)
                                .await
                                .unwrap();
                        }
                    }
                };
            });
        }

        Ok(())
    }
}
