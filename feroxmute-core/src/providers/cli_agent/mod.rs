//! CLI agent providers (Claude Code, Codex, Gemini CLI)
//!
//! These providers wrap CLI-based coding agents using:
//! - ACP (Agent Client Protocol) to drive the agent
//! - MCP (Model Context Protocol) to provide feroxmute tools

mod config;

pub use config::{CliAgentConfig, CliAgentType};
