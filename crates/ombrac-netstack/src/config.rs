use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use smoltcp::wire::{Ipv4Address, Ipv6Address};

const DEFAULT_IPV4_ADDR: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
const DEFAULT_IPV6_ADDR: Ipv6Address = Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1);

#[derive(Clone, Debug)]
pub struct Config {
    pub mtu: usize,
    pub channel_size: usize,

    pub tcp_send_buffer_size: usize,
    pub tcp_recv_buffer_size: usize,

    pub buffer_pool_size: usize,
    pub buffer_pool_default_buffer_size: usize,

    pub ipv4_addr: Ipv4Addr,
    pub ipv4_prefix_len: u8,
    pub ipv6_addr: Ipv6Addr,
    pub ipv6_prefix_len: u8,

    pub tcp_keep_alive: Duration,
    pub tcp_timeout: Duration,
    pub tcp_ack_delay: Duration,
    pub packet_batch_size: usize,
    pub ip_ttl: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1500,
            channel_size: 1024,
            tcp_send_buffer_size: 16 * 1024,
            tcp_recv_buffer_size: 16 * 1024,
            buffer_pool_size: 32,
            buffer_pool_default_buffer_size: 2 * 1024,
            ipv4_addr: DEFAULT_IPV4_ADDR,
            ipv4_prefix_len: 24,
            ipv6_addr: DEFAULT_IPV6_ADDR,
            ipv6_prefix_len: 64,

            tcp_timeout: Duration::from_secs(60),
            tcp_keep_alive: Duration::from_secs(28),
            tcp_ack_delay: Duration::from_millis(10),
            packet_batch_size: 32,
            ip_ttl: 64,
        }
    }
}
