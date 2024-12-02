mod client;
mod server;

pub mod io;
pub mod request;

pub use client::Client;
pub use server::Server;

pub trait Provider {
    type Item;

    fn fetch(&mut self) -> impl std::future::Future<Output = Option<Self::Item>> + Send;
}
