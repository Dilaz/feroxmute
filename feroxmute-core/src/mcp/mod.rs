//! MCP (Model Context Protocol) server implementation
//!
//! Provides tools to CLI agents via the MCP protocol.

mod protocol;
mod transport;

pub use protocol::*;
pub use transport::*;
