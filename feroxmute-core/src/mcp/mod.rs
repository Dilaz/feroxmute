//! MCP (Model Context Protocol) server implementation
//!
//! Provides tools to CLI agents via the MCP protocol.

mod protocol;
mod server;
mod transport;

pub use protocol::*;
pub use server::*;
pub use transport::*;
