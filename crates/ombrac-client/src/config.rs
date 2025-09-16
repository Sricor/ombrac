use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::builder::Styles;
use clap::builder::styling::{AnsiColor, Style};
use clap::{Parser, ValueEnum};
use figment::Figment;
use figment::providers::{Format, Json, Serialized};
use serde::{Deserialize, Serialize};

#[cfg(feature = "transport-quic")]
use ombrac_transport::quic::Congestion;

#[cfg(feature = "transport-quic")]
#[derive(ValueEnum, Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    Tls,
    MTls,
    Insecure,
}

#[derive(Deserialize, Serialize, Debug, Default, Parser, Clone)]
pub struct EndpointConfig {
    /// The address to bind for the HTTP/HTTPS server
    #[clap(long, value_name = "ADDR", help_heading = "Endpoint")]
    pub http: Option<SocketAddr>,

    /// The address to bind for the SOCKS server
    #[clap(long, value_name = "ADDR", help_heading = "Endpoint")]
    pub socks: Option<SocketAddr>,
}

#[derive(Deserialize, Serialize, Debug, Default, Parser, Clone)]
#[cfg(feature = "transport-quic")]
pub struct TransportConfig {
    /// The address to bind for transport
    #[clap(long, help_heading = "Transport", value_name = "ADDR")]
    pub bind: Option<SocketAddr>,

    /// Name of the server to connect (derived from `server` if not provided)
    #[clap(long, help_heading = "Transport", value_name = "STR")]
    pub server_name: Option<String>,

    /// Set the TLS mode for the connection
    /// tls: Standard TLS with server certificate verification
    /// m-tls: Mutual TLS with client and server certificate verification
    /// insecure: Skip server certificate verification (for testing only)
    #[clap(long, value_enum, help_heading = "Transport")]
    pub tls_mode: Option<TlsMode>,

    /// Path to the Certificate Authority (CA) certificate file
    /// in 'TLS' mode, if not provided, the system's default root certificates are used
    #[clap(long, help_heading = "Transport", value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,

    /// Path to the client's TLS certificate for mTLS
    #[clap(long, help_heading = "Transport", value_name = "FILE")]
    pub client_cert: Option<PathBuf>,

    /// Path to the client's TLS private key for mTLS
    #[clap(long, help_heading = "Transport", value_name = "FILE")]
    pub client_key: Option<PathBuf>,

    /// Enable 0-RTT for faster connection establishment (may reduce security)
    #[clap(long, help_heading = "Transport", action)]
    pub zero_rtt: Option<bool>,

    /// Application-Layer protocol negotiation (ALPN) protocols
    /// e.g. "h3,h3-29"
    #[clap(
        long,
        help_heading = "Transport",
        value_name = "PROTOCOLS",
        value_delimiter = ',',
        default_value = "h3",
    )]
    pub alpn_protocols: Option<Vec<Vec<u8>>>,

    /// Congestion control algorithm to use (e.g. bbr, cubic, newreno)
    #[clap(long, help_heading = "Transport", value_name = "ALGORITHM")]
    pub congestion: Option<Congestion>,

    /// Initial congestion window size in bytes
    #[clap(long, help_heading = "Transport", value_name = "NUM")]
    pub cwnd_init: Option<u64>,

    /// Maximum idle time (in milliseconds) before closing the connection
    /// 30 second default recommended by RFC 9308
    #[clap(
        long,
        help_heading = "Transport",
        value_name = "TIME",
        default_value = "30000"
    )]
    pub idle_timeout: Option<u64>,

    /// Keep-alive interval (in milliseconds)
    #[clap(
        long,
        help_heading = "Transport",
        value_name = "TIME",
        default_value = "8000"
    )]
    pub keep_alive: Option<u64>,

    /// Maximum number of bidirectional streams that can be open simultaneously
    #[clap(
        long,
        help_heading = "Transport",
        value_name = "NUM",
        default_value = "100"
    )]
    pub max_streams: Option<u64>,

    /// Try to resolve domain name to IPv4 addresses first
    #[clap(
        long,
        short = '4',
        help_heading = "Transport",
        action,
        conflicts_with = "prefer_ipv6"
    )]
    pub prefer_ipv4: bool,

    /// Try to resolve domain name to IPv6 addresses first
    #[clap(
        long,
        short = '6',
        help_heading = "Transport",
        action,
        conflicts_with = "prefer_ipv4"
    )]
    pub prefer_ipv6: bool,
}

#[derive(Deserialize, Serialize, Debug, Default, Parser, Clone)]
#[cfg(feature = "tracing")]
pub struct LoggingConfig {
    /// Logging level (e.g., INFO, WARN, ERROR)
    #[clap(
        long,
        help_heading = "Logging",
        value_name = "LEVEL",
        default_value = "INFO"
    )]
    pub log_level: Option<String>,

    /// Path to the log directory
    #[clap(long, value_name = "PATH", help_heading = "Logging")]
    pub log_dir: Option<PathBuf>,

    /// Prefix for log file names (only used when log-dir is specified)
    #[clap(long, value_name = "STR", help_heading = "Logging")]
    pub log_prefix: Option<PathBuf>,
}

/// A structure that mirrors the config file's layout.
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub secret: Option<String>,
    pub server: Option<String>,
    #[serde(flatten)]
    pub endpoint: EndpointConfig,
    #[cfg(feature = "transport-quic")]
    #[serde(flatten)]
    pub transport: TransportConfig,
    #[cfg(feature = "tracing")]
    #[serde(flatten)]
    pub logging: LoggingConfig,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = styles())]
pub struct Args {
    #[clap(
        long,
        short = 'c',
        value_name = "FILE",
        help = "Path to the JSON configuration file"
    )]
    pub config: Option<PathBuf>,
    #[clap(
        long,
        short = 'k',
        help_heading = "Required",
        value_name = "STR",
        required_unless_present = "config",
        help = "Protocol Secret"
    )]
    pub secret: Option<String>,
    #[clap(
        long,
        short = 's',
        help_heading = "Required",
        value_name = "ADDR",
        required_unless_present = "config",
        help = "Address of the server to connect to"
    )]
    pub server: Option<String>,
    #[clap(flatten)]
    pub endpoint: EndpointConfig,
    #[cfg(feature = "transport-quic")]
    #[clap(flatten)]
    pub transport: TransportConfig,
    #[cfg(feature = "tracing")]
    #[clap(flatten)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub secret: String,
    pub server: String,
    pub endpoint: EndpointConfig,
    #[cfg(feature = "transport-quic")]
    pub transport: TransportConfig,
    #[cfg(feature = "tracing")]
    pub logging: LoggingConfig,
}

pub fn load() -> Result<ServiceConfig, figment::Error> {
    let args = Args::parse();

    let mut figment = Figment::new();

    if let Some(config_path) = &args.config {
        if !config_path.exists() {
            let err = io::Error::new(
                io::ErrorKind::NotFound,
                format!("Configuration file not found: {}", config_path.display()),
            );
            return Err(figment::Error::from(err.to_string()));
        }

        figment = figment.merge(Json::file(config_path));
    }

    let cli_overrides = ConfigFile {
        secret: args.secret,
        server: args.server,
        endpoint: args.endpoint,
        #[cfg(feature = "transport-quic")]
        transport: args.transport,
        #[cfg(feature = "tracing")]
        logging: args.logging,
    };
    figment = figment.merge(Serialized::defaults(cli_overrides));

    let config: ConfigFile = figment.extract()?;

    let secret = config
        .secret
        .ok_or_else(|| figment::Error::from("the 'secret' field is required"))?;
    let server = config
        .server
        .ok_or_else(|| figment::Error::from("the 'server' field is required"))?;

    Ok(ServiceConfig {
        secret,
        server,
        endpoint: config.endpoint,
        #[cfg(feature = "transport-quic")]
        transport: config.transport,
        #[cfg(feature = "tracing")]
        logging: config.logging,
    })
}

fn styles() -> Styles {
    Styles::styled()
        .header(Style::new().bold().fg_color(Some(AnsiColor::Green.into())))
        .usage(Style::new().bold().fg_color(Some(AnsiColor::Green.into())))
        .literal(Style::new().bold().fg_color(Some(AnsiColor::Cyan.into())))
        .placeholder(Style::new().fg_color(Some(AnsiColor::Cyan.into())))
        .valid(Style::new().bold().fg_color(Some(AnsiColor::Cyan.into())))
        .invalid(Style::new().bold().fg_color(Some(AnsiColor::Yellow.into())))
        .error(Style::new().bold().fg_color(Some(AnsiColor::Red.into())))
}
