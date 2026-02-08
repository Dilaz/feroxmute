//! Integration tests for CLI agent providers

use feroxmute_core::providers::{CliAgentConfig, CliAgentType};
use std::path::PathBuf;

#[test]
fn test_cli_agent_config_defaults() {
    let config = CliAgentConfig::new(CliAgentType::ClaudeCode);
    assert_eq!(config.model, "claude-opus-4.5");
    assert_eq!(config.binary_path, PathBuf::from("claude-code-acp"));

    let config = CliAgentConfig::new(CliAgentType::Codex);
    assert_eq!(config.model, "gpt-5.2");
    assert_eq!(config.binary_path, PathBuf::from("codex-acp"));

    let config = CliAgentConfig::new(CliAgentType::GeminiCli);
    assert_eq!(config.model, "gemini-3-flash-preview");
    assert_eq!(config.binary_path, PathBuf::from("gemini"));
}

#[test]
fn test_cli_agent_config_custom_binary_path() {
    let config =
        CliAgentConfig::new(CliAgentType::ClaudeCode).with_binary_path("/usr/local/bin/claude");

    assert_eq!(config.binary_path, PathBuf::from("/usr/local/bin/claude"));
    assert_eq!(config.model, "claude-opus-4.5");
    assert_eq!(config.agent_type, CliAgentType::ClaudeCode);
}

#[test]
fn test_cli_agent_config_custom_model() {
    let config = CliAgentConfig::new(CliAgentType::ClaudeCode).with_model("claude-sonnet-4");

    assert_eq!(config.model, "claude-sonnet-4");
    assert_eq!(config.binary_path, PathBuf::from("claude-code-acp"));
}

#[test]
fn test_cli_agent_config_builder_chaining() {
    let config = CliAgentConfig::new(CliAgentType::Codex)
        .with_binary_path("/opt/codex/bin/codex")
        .with_model("gpt-5.0");

    assert_eq!(config.binary_path, PathBuf::from("/opt/codex/bin/codex"));
    assert_eq!(config.model, "gpt-5.0");
    assert_eq!(config.agent_type, CliAgentType::Codex);
}

#[test]
fn test_cli_agent_auth_hints() {
    assert_eq!(CliAgentType::ClaudeCode.auth_hint(), "claude login");
    assert_eq!(
        CliAgentType::Codex.auth_hint(),
        "set OPENAI_API_KEY or CODEX_API_KEY env var"
    );
    assert_eq!(CliAgentType::GeminiCli.auth_hint(), "gemini auth");
}

#[test]
fn test_cli_agent_type_equality() {
    assert_eq!(CliAgentType::ClaudeCode, CliAgentType::ClaudeCode);
    assert_ne!(CliAgentType::ClaudeCode, CliAgentType::Codex);
    assert_ne!(CliAgentType::Codex, CliAgentType::GeminiCli);
}
