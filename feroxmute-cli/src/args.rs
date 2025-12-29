//! CLI argument parsing

use clap::{ArgAction, Parser};
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

    /// LLM provider (anthropic, openai, litellm)
    #[arg(long)]
    pub provider: Option<String>,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

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

    /// Custom instruction to guide the engagement (supplements default behavior)
    #[arg(long)]
    pub instruction: Option<String>,
}
