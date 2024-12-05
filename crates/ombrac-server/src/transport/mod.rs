#[cfg(feature = "transport-quic")]
pub mod quic;

#[cfg(feature = "transport-tls")]
pub mod tls;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
