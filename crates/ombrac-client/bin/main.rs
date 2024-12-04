use std::error::Error;
use std::net::SocketAddr;

use clap::Parser;
use ombrac_client::endpoint::socks::Server as SocksServer;
use ombrac_client::transport::tls::{Builder, Tls};
use ombrac_client::Client;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    // Endpoint SOCKS
    /// Listening address for the SOCKS server.
    #[clap(
        long,
        default_value = "127.0.0.1:1080",
        value_name = "ADDR",
        help_heading = "Endpoint SOCKS"
    )]
    socks: SocketAddr,

    host: String,
    port: u16,
    domain: Option<String>,
    cafile: Option<String>,

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

    let ombrac_client = Client::new(tls_from_args(&args).await?);

    SocksServer::listen(args.socks, ombrac_client).await?;

    Ok(())
}

async fn tls_from_args(args: &Args) -> Result<Tls, Box<dyn Error>> {
    let builder = Builder::new(args.host.clone(), args.port);

    Ok(builder.build().await?)
}
