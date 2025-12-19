//! System prompts for specialized agents

use serde::Deserialize;
use std::path::Path;

use crate::{Error, Result};

/// Agent prompt configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AgentPrompt {
    pub prompt: String,
}

/// All agent prompts
#[derive(Debug, Clone, Deserialize)]
pub struct Prompts {
    pub orchestrator: AgentPrompt,
    pub recon: AgentPrompt,
    pub scanner: AgentPrompt,
    pub exploit: AgentPrompt,
    pub report: AgentPrompt,
    pub sast: AgentPrompt,
}

impl Prompts {
    /// Load prompts from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse prompts from TOML string
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| Error::Config(format!("Failed to parse prompts: {}", e)))
    }

    /// Load from default location (embedded)
    #[allow(clippy::expect_used)]
    pub fn default_prompts() -> Self {
        let content = include_str!("../../prompts.toml");
        Self::parse(content).expect("Embedded prompts.toml should be valid")
    }

    /// Get prompt for a specific agent
    pub fn get(&self, agent: &str) -> Option<&str> {
        match agent {
            "orchestrator" => Some(&self.orchestrator.prompt),
            "recon" => Some(&self.recon.prompt),
            "scanner" => Some(&self.scanner.prompt),
            "exploit" => Some(&self.exploit.prompt),
            "report" => Some(&self.report.prompt),
            "sast" => Some(&self.sast.prompt),
            _ => None,
        }
    }
}

impl Default for Prompts {
    fn default() -> Self {
        Self::default_prompts()
    }
}
