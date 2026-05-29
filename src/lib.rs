#![deny(unsafe_code)]

pub mod account;
pub mod client;
pub mod config;
pub mod digest;
pub mod engines;
pub mod error;
pub mod forwarder;
#[cfg(feature = "backend-gdbm")]
pub mod gdbm_engine;
pub(crate) mod local_time;
pub mod logging;

pub mod message;
pub mod mysql_cli;
pub mod mysql_engine;
#[cfg(feature = "backend-mysql")]
pub mod mysql_native;
pub mod redis_engine;
pub mod server;
pub use server::{serve_socket_until_shutdown, serve_with_shutdown};

pub(crate) mod python_repr;
pub mod sha1;

pub const VERSION: &str = "1.1.2";
pub const PROTO_NAME: &str = "pyzor";
pub const PROTO_VERSION: &str = "2.1";
pub const PROTO_MAJOR: i64 = 2;
pub const ANONYMOUS_USER: &str = "anonymous";
pub const MAX_TIMESTAMP_DIFFERENCE: i64 = 300;
pub const MAX_PACKET_SIZE: usize = 8192;

pub type Result<T> = std::result::Result<T, error::PyzorError>;
