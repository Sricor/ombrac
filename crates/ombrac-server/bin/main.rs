use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use ombrac_server::transport::tls::{Builder, Tls};
use ombrac_server::Server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Transport TLS
    /// Transport server listening address
    #[clap(long, help_heading = "Transport TLS", value_name = "ADDR")]
    listen: String,

    /// Path to the TLS certificate file for secure connections
    #[clap(long, help_heading = "Transport TLS", value_name = "FILE")]
    tls_cert: String,

    /// Path to the TLS private key file for secure connections
    #[clap(long, help_heading = "Transport TLS", value_name = "FILE")]
    tls_key: String,

    /// Logging level e.g., INFO, WARN, ERROR
    #[cfg(feature = "tracing")]
    #[clap(
        long,
        default_value = "WARN",
        value_name = "TRACE",
        help_heading = "Logging"
    )]
    tracing_level: tracing::Level,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_max_level(args.tracing_level)
        .init();

    let mut server = Server::new(tls_config_from_args(&args).await?);

    tracing::info!("server listening on {}", args.listen);

    server.listen().await?;

    Ok(())
}

async fn tls_config_from_args(args: &Args) -> Result<Tls, Box<dyn Error>> {
    let builder = Builder::new(args.listen.clone(), args.tls_cert.clone(), args.tls_key.clone());

    Ok(builder.build().await?)
}
