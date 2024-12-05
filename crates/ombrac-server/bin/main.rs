use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use ombrac_server::transport::tls::{Builder, Tls};
use ombrac_server::Server;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Transport TLS
    /// Transport server listening address
    #[clap(long, help_heading = "Transport TLS", value_name = "ADDR")]
    listen: SocketAddr,

    /// Path to the TLS certificate file for secure connections
    #[clap(long, help_heading = "Transport TLS", value_name = "FILE")]
    tls_cert: PathBuf,

    /// Path to the TLS private key file for secure connections
    #[clap(long, help_heading = "Transport TLS", value_name = "FILE")]
    tls_key: PathBuf,

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

    let mut server = Server::new(tls_from_args(&args).await?);

    #[cfg(feature = "tracing")]
    tracing::info!("server listening on {}", args.listen);

    server.listen().await?;

    Ok(())
}

async fn tls_from_args(args: &Args) -> Result<Tls, Box<dyn Error>> {
    let builder = Builder::new(
        args.listen.clone(),
        args.tls_cert.to_path_buf(),
        args.tls_key.to_path_buf(),
    );

    Ok(builder.build().await?)
}
