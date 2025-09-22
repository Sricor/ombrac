use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = match ombrac_server::config::load() {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("Failed to load configuration: {}", error);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                error.to_string(),
            ));
        }
    };

    run_from_cli(config).await
}

/// A high-level function to run the server from a command-line context.
/// It builds the service, waits for a Ctrl+C signal, and then gracefully shuts down.
pub async fn run_from_cli(config: ombrac_server::config::ServiceConfig) -> io::Result<()> {
    #[cfg(feature = "transport-quic")]
    {
        use ombrac_server::service::{QuicServiceBuilder, Service};

        use ombrac_transport::quic::{Connection as QuicConnection, server::Server as QuicServer};
        let service =
            Service::<QuicServer, QuicConnection>::build::<QuicServiceBuilder>(config.into())
                .await?;
        tokio::signal::ctrl_c().await?;
        service.shutdown().await;
    }

    Ok(())
}
