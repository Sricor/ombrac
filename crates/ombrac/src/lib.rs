pub mod address;
pub mod client;
pub mod connect;
pub mod io;
pub mod server;

const SECRET_LENGTH: usize = 32;

pub type Secret = [u8; SECRET_LENGTH];

pub mod prelude {
    pub use super::Secret;
    pub use super::address::Address;
    pub use super::client::{Client, Stream};
    pub use super::connect::Connect;
    pub use super::server::Server;
}
