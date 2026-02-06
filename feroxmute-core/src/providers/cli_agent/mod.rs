//! CLI agent providers (Claude Code, Codex, Gemini CLI)
//!
//! These providers wrap CLI-based coding agents using:
//! - ACP (Agent Client Protocol) to drive the agent
//! - MCP (Model Context Protocol) to provide feroxmute tools

mod bridge;
mod config;
mod provider;

pub use bridge::{AcpBridge, AcpEvent};
pub use config::{CliAgentConfig, CliAgentType};
pub use provider::CliAgentProvider;
