//! Configuration types for feroxmute engagements

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

/// Authentication type for target
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    None,
    Basic,
    Bearer,
    Cookie,
}

/// LLM provider selection
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    #[default]
    Anthropic,
    OpenAi,
    Cohere,
    LiteLlm,
    Perplexity,
    Gemini,
    #[serde(rename = "xai")]
    Xai,
    DeepSeek,
    Azure,
    Mira,
    Ollama,
    // CLI agent providers
    #[serde(rename = "claude-code")]
    ClaudeCode,
    Codex,
    #[serde(rename = "gemini-cli")]
    GeminiCli,
}

impl std::fmt::Display for ProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Cohere => "cohere",
            Self::LiteLlm => "litellm",
            Self::Perplexity => "perplexity",
            Self::Gemini => "gemini",
            Self::Xai => "xai",
            Self::DeepSeek => "deepseek",
            Self::Azure => "azure",
            Self::Mira => "mira",
            Self::Ollama => "ollama",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::GeminiCli => "gemini-cli",
        };
        f.write_str(s)
    }
}

impl FromStr for ProviderName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" => Ok(Self::Anthropic),
            "openai" => Ok(Self::OpenAi),
            "cohere" => Ok(Self::Cohere),
            "litellm" => Ok(Self::LiteLlm),
            "perplexity" => Ok(Self::Perplexity),
            "gemini" => Ok(Self::Gemini),
            "xai" => Ok(Self::Xai),
            "deepseek" => Ok(Self::DeepSeek),
            "azure" => Ok(Self::Azure),
            "mira" => Ok(Self::Mira),
            "ollama" => Ok(Self::Ollama),
            "claude-code" => Ok(Self::ClaudeCode),
            "codex" => Ok(Self::Codex),
            "gemini-cli" => Ok(Self::GeminiCli),
            _ => Err(format!("unknown provider: {s}")),
        }
    }
}

/// Target configuration (optional in config file - use CLI --target instead)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Capability flags (additive permissions)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitiesConfig {
    /// Enable subdomain enumeration and asset discovery
    #[serde(default)]
    pub discover: bool,
    /// Enable port scanning
    #[serde(default)]
    pub portscan: bool,
    /// Enable network-level scanning
    #[serde(default)]
    pub network: bool,
}

/// Engagement constraints
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub no_exploit: bool,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

/// Authentication configuration
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default, rename = "type")]
    pub auth_type: AuthType,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("auth_type", &self.auth_type)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// LLM provider configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: ProviderName,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("name", &self.name)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: ProviderName::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            api_key: None,
            base_url: None,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_session_dir")]
    pub session_dir: PathBuf,
    #[serde(default)]
    pub export_html: bool,
    #[serde(default)]
    pub export_pdf: bool,
}

fn default_session_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".feroxmute")
        .join("sessions")
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            session_dir: default_session_dir(),
            export_html: false,
            export_pdf: false,
        }
    }
}

/// Complete engagement configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngagementConfig {
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub target: TargetConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub output: OutputConfig,
    /// Target LLM configuration for LLM penetration testing
    #[serde(default)]
    pub target_llm: Option<ProviderConfig>,
}

impl EngagementConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse configuration from TOML string
    pub fn parse(content: &str) -> crate::Result<Self> {
        Ok(toml::from_str(content)?)
    }

    /// Load configuration from default locations with cascade:
    /// 1. ./feroxmute.toml (local override)
    /// 2. ~/.feroxmute/config.toml (global defaults)
    /// 3. Built-in defaults
    pub fn load_default() -> Self {
        // Try local config first (warn: could be attacker-placed in CWD)
        if let Ok(config) = Self::from_file("feroxmute.toml") {
            tracing::warn!("Loading configuration from local feroxmute.toml in current directory");
            return config;
        }

        // Try global config
        if let Some(home) = dirs::home_dir() {
            let global_path = home.join(".feroxmute").join("config.toml");
            if let Ok(config) = Self::from_file(&global_path) {
                return config;
            }
        }

        // Fall back to defaults
        Self::default()
    }

    /// Get the path to the global config file
    pub fn global_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".feroxmute").join("config.toml"))
    }

    /// Expand environment variables in token fields
    pub fn expand_env_vars(&mut self) {
        if let Some(ref token) = self.auth.token
            && token.starts_with("${")
            && token.ends_with("}")
        {
            let var_name = &token[2..token.len() - 1];
            if let Ok(value) = std::env::var(var_name) {
                self.auth.token = Some(value);
            }
        }
        if let Some(ref key) = self.provider.api_key
            && key.starts_with("${")
            && key.ends_with("}")
        {
            let var_name = &key[2..key.len() - 1];
            if let Ok(value) = std::env::var(var_name) {
                self.provider.api_key = Some(value);
            }
        }
        if let Some(ref mut target) = self.target_llm
            && let Some(ref key) = target.api_key
            && key.starts_with("${")
            && key.ends_with("}")
        {
            let var_name = &key[2..key.len() - 1];
            if let Ok(value) = std::env::var(var_name) {
                target.api_key = Some(value);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider_only_config() {
        let toml = r#"
[provider]
name = "openai"
model = "gpt-4o"
"#;
        let config =
            EngagementConfig::parse(toml).expect("valid provider-only config should parse");
        assert_eq!(config.provider.name, ProviderName::OpenAi);
        assert_eq!(config.provider.model, "gpt-4o");
        assert_eq!(config.target.host, ""); // Target defaults to empty
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[target]
host = "example.com"
"#;
        let config = EngagementConfig::parse(toml).expect("valid config");
        assert_eq!(config.target.host, "example.com");
        assert!(!config.capabilities.discover);
        assert!(!config.capabilities.portscan);
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[target]
host = "example.com"
ports = [80, 443, 8080]

[capabilities]
discover = true
portscan = true
network = true

[constraints]
passive = false
no_exploit = true
rate_limit = 10

[auth]
type = "bearer"
token = "secret123"

[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"

[output]
export_html = true
"#;
        let config = EngagementConfig::parse(toml).expect("full config");
        assert_eq!(config.target.host, "example.com");
        assert_eq!(config.target.ports, vec![80, 443, 8080]);
        assert!(config.capabilities.discover);
        assert!(config.capabilities.portscan);
        assert!(config.capabilities.network);
        assert!(config.constraints.no_exploit);
        assert_eq!(config.constraints.rate_limit, Some(10));
        assert_eq!(config.auth.auth_type, AuthType::Bearer);
        assert!(config.output.export_html);
    }

    #[test]
    fn test_env_var_expansion() {
        temp_env::with_var("TEST_TOKEN", Some("expanded_value"), || {
            let toml = r#"
[target]
host = "example.com"

[auth]
type = "bearer"
token = "${TEST_TOKEN}"
"#;
            let mut config =
                EngagementConfig::parse(toml).expect("config with env var should parse");
            config.expand_env_vars();
            assert_eq!(config.auth.token, Some("expanded_value".to_string()));
        });
    }

    #[test]
    fn test_parse_config_with_api_key() {
        let toml = r#"
[target]
host = "example.com"

[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"
api_key = "sk-ant-test123"
"#;
        let config = EngagementConfig::parse(toml).expect("config with api_key should parse");
        assert_eq!(config.provider.name, ProviderName::Anthropic);
        assert_eq!(config.provider.api_key, Some("sk-ant-test123".to_string()));
    }

    #[test]
    fn test_global_config_path() {
        let path = EngagementConfig::global_config_path();
        assert!(path.is_some());
        let path = path.expect("global config path should exist");
        assert!(path.ends_with(".feroxmute/config.toml"));
    }

    #[test]
    fn test_parse_target_llm_config() {
        let toml = r#"
[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"

[target_llm]
name = "openai"
model = "gpt-4"
base_url = "https://custom.endpoint.com/v1"
"#;
        let config = EngagementConfig::parse(toml).expect("valid target_llm config should parse");
        assert!(config.target_llm.is_some());
        let target = config.target_llm.unwrap();
        assert_eq!(target.name, ProviderName::OpenAi);
        assert_eq!(target.model, "gpt-4");
        assert_eq!(
            target.base_url.as_deref(),
            Some("https://custom.endpoint.com/v1")
        );
    }

    #[test]
    fn test_target_llm_optional() {
        let toml = r#"
[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"
"#;
        let config = EngagementConfig::parse(toml).expect("config without target_llm should parse");
        assert!(config.target_llm.is_none());
    }

    #[test]
    fn test_target_llm_env_expansion() {
        temp_env::with_var("TEST_TARGET_LLM_KEY", Some("sk-test-key-123"), || {
            let toml = r#"
[target_llm]
name = "openai"
model = "gpt-4"
api_key = "${TEST_TARGET_LLM_KEY}"
"#;
            let mut config = EngagementConfig::parse(toml).expect("should parse");
            config.expand_env_vars();
            let target = config.target_llm.unwrap();
            assert_eq!(target.api_key.as_deref(), Some("sk-test-key-123"));
        });
    }

    #[test]
    fn test_provider_name_display() {
        assert_eq!(ProviderName::Anthropic.to_string(), "anthropic");
        assert_eq!(ProviderName::OpenAi.to_string(), "openai");
        assert_eq!(ProviderName::Xai.to_string(), "xai");
        assert_eq!(ProviderName::ClaudeCode.to_string(), "claude-code");
        assert_eq!(ProviderName::GeminiCli.to_string(), "gemini-cli");
        assert_eq!(ProviderName::LiteLlm.to_string(), "litellm");
        assert_eq!(ProviderName::DeepSeek.to_string(), "deepseek");
        assert_eq!(ProviderName::Cohere.to_string(), "cohere");
        assert_eq!(ProviderName::Gemini.to_string(), "gemini");
        assert_eq!(ProviderName::Azure.to_string(), "azure");
        assert_eq!(ProviderName::Mira.to_string(), "mira");
        assert_eq!(ProviderName::Perplexity.to_string(), "perplexity");
        assert_eq!(ProviderName::Ollama.to_string(), "ollama");
        assert_eq!(ProviderName::Codex.to_string(), "codex");
    }

    #[test]
    fn test_provider_name_fromstr_roundtrip() {
        let all_variants = [
            ProviderName::Anthropic,
            ProviderName::OpenAi,
            ProviderName::Cohere,
            ProviderName::LiteLlm,
            ProviderName::Perplexity,
            ProviderName::Gemini,
            ProviderName::Xai,
            ProviderName::DeepSeek,
            ProviderName::Azure,
            ProviderName::Mira,
            ProviderName::Ollama,
            ProviderName::ClaudeCode,
            ProviderName::Codex,
            ProviderName::GeminiCli,
        ];
        for variant in &all_variants {
            let s = variant.to_string();
            let parsed: ProviderName = s.parse().unwrap();
            assert_eq!(&parsed, variant, "round-trip failed for {s}");
        }
    }

    #[test]
    fn test_provider_name_fromstr_case_insensitive() {
        assert_eq!(
            "ANTHROPIC".parse::<ProviderName>().unwrap(),
            ProviderName::Anthropic
        );
        assert_eq!(
            "OpenAI".parse::<ProviderName>().unwrap(),
            ProviderName::OpenAi
        );
        assert_eq!(
            "Claude-Code".parse::<ProviderName>().unwrap(),
            ProviderName::ClaudeCode
        );
        assert_eq!(
            "GEMINI-CLI".parse::<ProviderName>().unwrap(),
            ProviderName::GeminiCli
        );
    }

    #[test]
    fn test_provider_name_fromstr_unknown() {
        assert!("unknown".parse::<ProviderName>().is_err());
        assert!("".parse::<ProviderName>().is_err());
        assert!("not-a-provider".parse::<ProviderName>().is_err());
    }
}
