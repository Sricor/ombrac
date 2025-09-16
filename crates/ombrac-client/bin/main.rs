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

    ombrac_client::service::run_from_cli(config).await
}
