//! MCP (Model Context Protocol) server implementation
//!
//! Provides tools to CLI agents via the MCP protocol.

pub mod http;
mod protocol;
mod server;
pub mod stdio_proxy;
pub mod tools;
mod transport;

pub use protocol::*;
pub use server::*;
pub use stdio_proxy::run_stdio_proxy;
pub use transport::*;
