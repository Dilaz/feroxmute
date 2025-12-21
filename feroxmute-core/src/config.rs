//! Configuration types for feroxmute engagements

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Testing scope
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Web,
    Network,
    Full,
}

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
}

/// Target configuration (optional in config file - use CLI --target instead)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Engagement constraints
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub no_exploit: bool,
    #[serde(default)]
    pub no_portscan: bool,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// LLM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: ProviderName,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
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
    pub target: TargetConfig,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub output: OutputConfig,
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
        // Try local config first
        if let Ok(config) = Self::from_file("feroxmute.toml") {
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
        if let Some(ref token) = self.auth.token {
            if token.starts_with("${") && token.ends_with("}") {
                let var_name = &token[2..token.len() - 1];
                if let Ok(value) = std::env::var(var_name) {
                    self.auth.token = Some(value);
                }
            }
        }
        if let Some(ref key) = self.provider.api_key {
            if key.starts_with("${") && key.ends_with("}") {
                let var_name = &key[2..key.len() - 1];
                if let Ok(value) = std::env::var(var_name) {
                    self.provider.api_key = Some(value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider_only_config() {
        let toml = r#"
[provider]
name = "openai"
model = "gpt-4o"
"#;
        let config = EngagementConfig::parse(toml).unwrap();
        assert_eq!(config.provider.name, ProviderName::OpenAi);
        assert_eq!(config.provider.model, "gpt-4o");
        assert_eq!(config.target.host, ""); // Target defaults to empty
    }

    #[test]
    fn test_parse_config_with_target() {
        let toml = r#"
[target]
host = "example.com"
"#;
        let config = EngagementConfig::parse(toml).unwrap();
        assert_eq!(config.target.host, "example.com");
        assert_eq!(config.target.scope, Scope::Web);
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[target]
host = "example.com"
scope = "web"
ports = [80, 443, 8080]

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
        let config = EngagementConfig::parse(toml).unwrap();
        assert_eq!(config.target.host, "example.com");
        assert_eq!(config.target.ports, vec![80, 443, 8080]);
        assert!(config.constraints.no_exploit);
        assert_eq!(config.constraints.rate_limit, Some(10));
        assert_eq!(config.auth.auth_type, AuthType::Bearer);
        assert!(config.output.export_html);
    }

    #[test]
    fn test_env_var_expansion() {
        std::env::set_var("TEST_TOKEN", "expanded_value");
        let toml = r#"
[target]
host = "example.com"

[auth]
type = "bearer"
token = "${TEST_TOKEN}"
"#;
        let mut config = EngagementConfig::parse(toml).unwrap();
        config.expand_env_vars();
        assert_eq!(config.auth.token, Some("expanded_value".to_string()));
        std::env::remove_var("TEST_TOKEN");
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
        let config = EngagementConfig::parse(toml).unwrap();
        assert_eq!(config.provider.name, ProviderName::Anthropic);
        assert_eq!(config.provider.api_key, Some("sk-ant-test123".to_string()));
    }

    #[test]
    fn test_global_config_path() {
        let path = EngagementConfig::global_config_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.ends_with(".feroxmute/config.toml"));
    }
}
