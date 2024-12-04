use std::future::Future;

pub mod io;
pub mod request;

pub trait Provider {
    type Item;

    fn fetch(&mut self) -> impl Future<Output = Option<Self::Item>> + Send;
}
