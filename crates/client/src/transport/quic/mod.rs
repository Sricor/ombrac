mod client;
mod connection;
mod stream;

use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

pub use client::impl_s2n_quic::NoiseQuic;

// QUIC Config
pub struct Config {
    bind: Option<SocketAddr>,

    server_name: Option<String>,
    server_address: String,

    tls_cert: Option<String>,

    initial_congestion_window: Option<u32>,

    max_multiplex: Option<u64>,
    max_multiplex_interval: Option<(u64, Duration)>,
    max_handshake_duration: Option<Duration>,
    max_idle_timeout: Option<Duration>,
    max_keep_alive_period: Option<Duration>,
    max_open_bidirectional_streams: Option<u64>,

    bidirectional_local_data_window: Option<u64>,
    bidirectional_remote_data_window: Option<u64>,
}

impl Config {
    pub fn new<T>(server_address: String) -> Self
    where
        T: Into<SocketAddr>,
    {
        Config {
            bind: None,
            server_name: None,
            server_address,
            tls_cert: None,
            initial_congestion_window: None,
            max_multiplex: None,
            max_multiplex_interval: None,
            max_handshake_duration: None,
            max_idle_timeout: None,
            max_keep_alive_period: None,
            max_open_bidirectional_streams: None,
            bidirectional_local_data_window: None,
            bidirectional_remote_data_window: None,
        }
    }

    pub fn with_server_name(mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
        self
    }

    pub fn with_bind(mut self, bind: SocketAddr) -> Self {
        self.bind = Some(bind);
        self
    }

    pub fn with_tls_cert(mut self, tls_cert: String) -> Self {
        self.tls_cert = Some(tls_cert);
        self
    }

    pub fn with_initial_congestion_window(mut self, window: u32) -> Self {
        self.initial_congestion_window = Some(window);
        self
    }

    pub fn with_max_multiplex(mut self, multiplex: u64) -> Self {
        self.max_multiplex = Some(multiplex);
        self
    }

    pub fn with_max_max_multiplex_interval(mut self, multiplex_interval: (u64, Duration)) -> Self {
        self.max_multiplex_interval = Some(multiplex_interval);
        self
    }

    pub fn with_max_handshake_duration(mut self, duration: Duration) -> Self {
        self.max_handshake_duration = Some(duration);
        self
    }

    pub fn with_max_idle_timeout(mut self, duration: Duration) -> Self {
        self.max_idle_timeout = Some(duration);
        self
    }

    pub fn with_max_keep_alive_period(mut self, duration: Duration) -> Self {
        self.max_keep_alive_period = Some(duration);
        self
    }

    pub fn with_max_open_bidirectional_streams(mut self, streams: u64) -> Self {
        self.max_open_bidirectional_streams = Some(streams);
        self
    }

    pub fn with_bidirectional_local_data_window(mut self, window: u64) -> Self {
        self.bidirectional_local_data_window = Some(window);
        self
    }

    pub fn with_bidirectional_remote_data_window(mut self, window: u64) -> Self {
        self.bidirectional_remote_data_window = Some(window);
        self
    }
}
