//! CLI argument parsing

use clap::{ArgAction, Parser};
use feroxmute_core::config::ReasoningEffort;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "feroxmute")]
#[command(author, version, about = "LLM-powered penetration testing framework")]
pub struct Args {
    /// Target domains, IPs, directories, or git URLs (can be repeated)
    #[arg(long, action = ArgAction::Append)]
    pub target: Vec<String>,

    /// Explicit source directory for the primary target
    #[arg(long)]
    pub source: Option<PathBuf>,

    /// Treat all targets as separate engagements (skip relationship detection)
    #[arg(long)]
    pub separate: bool,

    /// Run static analysis only (no web testing)
    #[arg(long)]
    pub sast_only: bool,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Interactive setup wizard
    #[arg(long)]
    pub wizard: bool,

    /// Resume a previous session
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// List available sessions
    #[arg(long)]
    pub list_sessions: bool,

    /// Enable subdomain enumeration and asset discovery
    #[arg(long)]
    pub discover: bool,

    /// Enable port scanning (naabu, nmap)
    #[arg(long)]
    pub portscan: bool,

    /// Enable network-level scanning beyond HTTP
    #[arg(long)]
    pub network: bool,

    /// Recon and scan only, no exploitation
    #[arg(long)]
    pub no_exploit: bool,

    /// Passive recon only
    #[arg(long)]
    pub passive: bool,

    /// Limit port range (comma-separated)
    #[arg(long)]
    pub ports: Option<String>,

    /// Max requests per second
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// LLM provider (anthropic, openai, gemini, cohere, xai, deepseek, azure,
    /// perplexity, mira, ollama, litellm, claude-code, codex, gemini-cli)
    #[arg(long)]
    pub provider: Option<String>,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

    /// OpenAI/LiteLLM reasoning effort (none, minimal, low, medium, high, xhigh, max)
    #[arg(long)]
    pub reasoning_effort: Option<ReasoningEffort>,

    /// Path to CLI agent binary (for claude-code, codex, gemini-cli providers)
    #[arg(long, value_name = "PATH")]
    pub cli_path: Option<PathBuf>,

    /// Output directory for session
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Export HTML report
    #[arg(long)]
    pub html: bool,

    /// Export PDF report
    #[arg(long)]
    pub pdf: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Enable debug logging and diagnostic TUI feed entries
    #[arg(long)]
    pub debug: bool,

    /// Force plain ASCII, 16-color output (no Unicode/truecolor)
    #[arg(long)]
    pub ascii: bool,

    /// Custom instruction to guide the engagement (supplements default behavior)
    #[arg(long)]
    pub instruction: Option<String>,

    /// Target LLM provider for penetration testing (openai, anthropic, gemini, etc.)
    #[arg(long)]
    pub target_llm: Option<String>,

    /// Target LLM model name
    #[arg(long)]
    pub target_model: Option<String>,

    /// Target LLM API key (or use TARGET_LLM_API_KEY env var)
    #[arg(long)]
    pub target_api_key: Option<String>,

    /// Target LLM custom API endpoint
    #[arg(long)]
    pub target_base_url: Option<String>,

    /// Skip network testing, only test the target LLM
    #[arg(long)]
    pub llm_only: bool,

    /// Internal: run as an stdio↔HTTP MCP proxy for stdio-only ACP agents.
    ///
    /// Used automatically by feroxmute when a CLI agent (e.g. claude-code)
    /// only supports stdio MCP servers. The bearer token is read from the
    /// `FEROXMUTE_MCP_TOKEN` environment variable.
    #[arg(long, hide = true)]
    pub mcp_stdio_proxy: bool,

    /// Internal: HTTP MCP server URL for `--mcp-stdio-proxy`.
    #[arg(long, hide = true, value_name = "URL")]
    pub mcp_proxy_url: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn reasoning_effort_accepts_low_and_max() {
        let low = Args::try_parse_from(["feroxmute", "--reasoning-effort", "low"]).unwrap();
        assert_eq!(low.reasoning_effort, Some(ReasoningEffort::Low));

        let max = Args::try_parse_from(["feroxmute", "--reasoning-effort", "max"]).unwrap();
        assert_eq!(max.reasoning_effort, Some(ReasoningEffort::Max));
    }

    #[test]
    fn reasoning_effort_distinguishes_unset_from_explicit_none() {
        let unset = Args::try_parse_from(["feroxmute"]).unwrap();
        assert_eq!(unset.reasoning_effort, None);

        let disabled = Args::try_parse_from(["feroxmute", "--reasoning-effort", "none"]).unwrap();
        assert_eq!(disabled.reasoning_effort, Some(ReasoningEffort::None));
    }

    #[test]
    fn reasoning_effort_rejects_typos() {
        let error = Args::try_parse_from(["feroxmute", "--reasoning-effort", "hgh"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }
}
