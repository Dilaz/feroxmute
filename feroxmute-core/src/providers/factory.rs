//! Provider factory for creating LLM provider instances

use std::sync::Arc;

use crate::config::{ProviderConfig, ProviderName};
use crate::state::MetricsTracker;
use crate::{Error, Result};

use super::{AnthropicProvider, LlmProvider, OpenAiProvider};

/// Create a provider from configuration
pub fn create_provider(
    config: &ProviderConfig,
    metrics: MetricsTracker,
) -> Result<Arc<dyn LlmProvider>> {
    match config.name {
        ProviderName::Anthropic => {
            // Use config api_key if set, otherwise fall back to env var
            if let Some(ref api_key) = config.api_key {
                std::env::set_var("ANTHROPIC_API_KEY", api_key);
            }
            let provider = AnthropicProvider::new(&config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::OpenAi => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .ok_or_else(|| Error::Provider("OPENAI_API_KEY not set".to_string()))?;

            let provider = if let Some(ref base_url) = config.base_url {
                OpenAiProvider::with_base_url(api_key, base_url, &config.model, metrics)?
            } else {
                std::env::set_var("OPENAI_API_KEY", &api_key);
                OpenAiProvider::new(&config.model, metrics)?
            };
            Ok(Arc::new(provider))
        }
        ProviderName::LiteLlm => {
            let base_url = config
                .base_url
                .clone()
                .unwrap_or_else(|| "http://localhost:4000".to_string());
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("LITELLM_API_KEY").ok())
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .ok_or_else(|| {
                    Error::Provider("LITELLM_API_KEY or OPENAI_API_KEY not set".to_string())
                })?;
            let provider =
                OpenAiProvider::with_base_url(api_key, base_url, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Cohere => Err(Error::Provider(
            "Cohere provider not implemented".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_anthropic_requires_api_key() {
        // Ensure API key is not set
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::Anthropic,
            model: "claude-3-sonnet".to_string(),
            api_key: None,
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_err());

        // Restore
        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }

    #[test]
    fn test_create_openai_requires_api_key() {
        let original = std::env::var("OPENAI_API_KEY").ok();
        std::env::remove_var("OPENAI_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::OpenAi,
            model: "gpt-4o".to_string(),
            api_key: None,
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_err());

        if let Some(key) = original {
            std::env::set_var("OPENAI_API_KEY", key);
        }
    }

    #[test]
    fn test_cohere_not_implemented() {
        let config = ProviderConfig {
            name: ProviderName::Cohere,
            model: "command".to_string(),
            api_key: None,
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    fn test_anthropic_uses_config_api_key() {
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::Anthropic,
            model: "claude-3-sonnet".to_string(),
            api_key: Some("test-key-from-config".to_string()),
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_ok());

        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }

    #[test]
    fn test_openai_uses_config_api_key() {
        let original = std::env::var("OPENAI_API_KEY").ok();
        std::env::remove_var("OPENAI_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::OpenAi,
            model: "gpt-4o".to_string(),
            api_key: Some("test-key-from-config".to_string()),
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_ok());

        if let Some(key) = original {
            std::env::set_var("OPENAI_API_KEY", key);
        }
    }

    #[test]
    fn test_litellm_uses_config_api_key() {
        let original_litellm = std::env::var("LITELLM_API_KEY").ok();
        let original_openai = std::env::var("OPENAI_API_KEY").ok();
        std::env::remove_var("LITELLM_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::LiteLlm,
            model: "gpt-4o".to_string(),
            api_key: Some("test-key-from-config".to_string()),
            base_url: Some("http://localhost:4000".to_string()),
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_ok());

        if let Some(key) = original_litellm {
            std::env::set_var("LITELLM_API_KEY", key);
        }
        if let Some(key) = original_openai {
            std::env::set_var("OPENAI_API_KEY", key);
        }
    }
}
