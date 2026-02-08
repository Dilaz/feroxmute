//! CLI agent configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of CLI agent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CliAgentType {
    ClaudeCode,
    Codex,
    GeminiCli,
}

impl CliAgentType {
    /// Get the provider name string
    pub fn provider_name(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::GeminiCli => "gemini-cli",
        }
    }

    /// Get the default binary name
    ///
    /// Note: Codex does not speak ACP natively — the `codex-acp` adapter
    /// binary (maintained by Zed Industries) translates between ACP and
    /// Codex's internal protocol.
    pub fn default_binary(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code-acp",
            Self::Codex => "codex-acp",
            Self::GeminiCli => "gemini",
        }
    }

    /// Get the default model
    pub fn default_model(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-opus-4.5",
            Self::Codex => "gpt-5.2",
            Self::GeminiCli => "gemini-3-flash-preview",
        }
    }

    /// Get the auth command hint
    pub fn auth_hint(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude login",
            Self::Codex => "set OPENAI_API_KEY or CODEX_API_KEY env var",
            Self::GeminiCli => "gemini auth",
        }
    }
}

/// Configuration for a CLI agent provider
#[derive(Debug, Clone)]
pub struct CliAgentConfig {
    pub agent_type: CliAgentType,
    pub binary_path: PathBuf,
    pub model: String,
}

impl CliAgentConfig {
    /// Create config with defaults for the given agent type
    pub fn new(agent_type: CliAgentType) -> Self {
        Self {
            binary_path: PathBuf::from(agent_type.default_binary()),
            model: agent_type.default_model().to_string(),
            agent_type,
        }
    }

    /// Set custom binary path
    pub fn with_binary_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary_path = path.into();
        self
    }

    /// Set custom model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_type_names() {
        assert_eq!(CliAgentType::ClaudeCode.provider_name(), "claude-code");
        assert_eq!(CliAgentType::Codex.provider_name(), "codex");
        assert_eq!(CliAgentType::GeminiCli.provider_name(), "gemini-cli");
    }

    #[test]
    fn test_default_models() {
        assert_eq!(CliAgentType::ClaudeCode.default_model(), "claude-opus-4.5");
        assert_eq!(CliAgentType::Codex.default_model(), "gpt-5.2");
        assert_eq!(
            CliAgentType::GeminiCli.default_model(),
            "gemini-3-flash-preview"
        );
    }

    #[test]
    fn test_config_builder() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode)
            .with_binary_path("/usr/local/bin/claude")
            .with_model("claude-sonnet-4");

        assert_eq!(config.binary_path, PathBuf::from("/usr/local/bin/claude"));
        assert_eq!(config.model, "claude-sonnet-4");
    }

    #[test]
    fn test_cli_agent_type_serde_kebab_case() {
        for variant in [
            CliAgentType::ClaudeCode,
            CliAgentType::Codex,
            CliAgentType::GeminiCli,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let roundtrip: CliAgentType = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, variant);
        }
        // Verify kebab-case format
        assert_eq!(
            serde_json::to_string(&CliAgentType::ClaudeCode).unwrap(),
            "\"claude-code\""
        );
        assert_eq!(
            serde_json::to_string(&CliAgentType::GeminiCli).unwrap(),
            "\"gemini-cli\""
        );
    }
}
