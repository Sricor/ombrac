use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = match ombrac_client::config::load() {
        Ok(cfg) => cfg,
        Err(error) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                error.to_string(),
            ));
        }
    };

    run_from_cli(config).await
}

/// A high-level function to run the client from a command-line context.
/// It builds the session, waits for a Ctrl+C signal, and then gracefully shuts down.
pub async fn run_from_cli(config: ombrac_client::config::ServiceConfig) -> io::Result<()> {
    #[cfg(feature = "transport-quic")]
    {
        use ombrac_client::service::{QuicServiceBuilder, Service};
        let session = Service::build::<QuicServiceBuilder>(config.into()).await?;
        tokio::signal::ctrl_c().await?;
        session.shutdown().await;
    }
    Ok(())
}
