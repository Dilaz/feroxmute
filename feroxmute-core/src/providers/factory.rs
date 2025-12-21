//! Provider factory for creating LLM provider instances

use std::sync::Arc;

use crate::config::{ProviderConfig, ProviderName};
use crate::state::MetricsTracker;
use crate::{Error, Result};

use super::{
    AnthropicProvider, AzureProvider, CohereProvider, DeepSeekProvider, GeminiProvider,
    LlmProvider, MiraProvider, OllamaProvider, OpenAiProvider, PerplexityProvider, XaiProvider,
};

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
        ProviderName::Cohere => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("COHERE_API_KEY").ok())
                .ok_or_else(|| Error::Provider("COHERE_API_KEY not set".to_string()))?;
            let provider = CohereProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Perplexity => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("PERPLEXITY_API_KEY").ok())
                .ok_or_else(|| Error::Provider("PERPLEXITY_API_KEY not set".to_string()))?;
            let provider = PerplexityProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Gemini => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("GEMINI_API_KEY").ok())
                .or_else(|| std::env::var("GOOGLE_API_KEY").ok())
                .ok_or_else(|| {
                    Error::Provider("GEMINI_API_KEY or GOOGLE_API_KEY not set".to_string())
                })?;
            let provider = GeminiProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Xai => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("XAI_API_KEY").ok())
                .ok_or_else(|| Error::Provider("XAI_API_KEY not set".to_string()))?;
            let provider = XaiProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::DeepSeek => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("DEEPSEEK_API_KEY").ok())
                .ok_or_else(|| Error::Provider("DEEPSEEK_API_KEY not set".to_string()))?;
            let provider = DeepSeekProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Azure => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("AZURE_OPENAI_API_KEY").ok())
                .ok_or_else(|| Error::Provider("AZURE_OPENAI_API_KEY not set".to_string()))?;
            let endpoint = config
                .base_url
                .clone()
                .or_else(|| std::env::var("AZURE_OPENAI_ENDPOINT").ok())
                .ok_or_else(|| {
                    Error::Provider("Azure requires base_url (endpoint) to be set".to_string())
                })?;
            let provider = AzureProvider::with_api_key(api_key, endpoint, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Mira => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("MIRA_API_KEY").ok())
                .ok_or_else(|| Error::Provider("MIRA_API_KEY not set".to_string()))?;
            let provider = MiraProvider::with_api_key(api_key, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Ollama => {
            // Ollama doesn't require API key by default, uses localhost:11434
            let provider = if let Some(ref base_url) = config.base_url {
                OllamaProvider::with_base_url(base_url, &config.model, metrics)?
            } else {
                // Try OLLAMA_API_BASE_URL env var, fall back to default localhost
                match std::env::var("OLLAMA_API_BASE_URL") {
                    Ok(base_url) => {
                        OllamaProvider::with_base_url(base_url, &config.model, metrics)?
                    }
                    Err(_) => OllamaProvider::new(&config.model, metrics)?,
                }
            };
            Ok(Arc::new(provider))
        }
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
    fn test_cohere_requires_api_key() {
        let original = std::env::var("COHERE_API_KEY").ok();
        std::env::remove_var("COHERE_API_KEY");

        let config = ProviderConfig {
            name: ProviderName::Cohere,
            model: "command-r-plus".to_string(),
            api_key: None,
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_err());

        if let Some(key) = original {
            std::env::set_var("COHERE_API_KEY", key);
        }
    }

    #[test]
    fn test_azure_requires_endpoint() {
        let original_key = std::env::var("AZURE_OPENAI_API_KEY").ok();
        let original_endpoint = std::env::var("AZURE_OPENAI_ENDPOINT").ok();
        std::env::remove_var("AZURE_OPENAI_ENDPOINT");

        let config = ProviderConfig {
            name: ProviderName::Azure,
            model: "gpt-4o".to_string(),
            api_key: Some("test-key".to_string()),
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("base_url"));

        if let Some(key) = original_key {
            std::env::set_var("AZURE_OPENAI_API_KEY", key);
        }
        if let Some(endpoint) = original_endpoint {
            std::env::set_var("AZURE_OPENAI_ENDPOINT", endpoint);
        }
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

    #[test]
    fn test_ollama_works_without_api_key() {
        // Ollama should work without any API key (uses localhost by default)
        let config = ProviderConfig {
            name: ProviderName::Ollama,
            model: "llama3.2".to_string(),
            api_key: None,
            base_url: None,
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_ollama_with_custom_base_url() {
        let config = ProviderConfig {
            name: ProviderName::Ollama,
            model: "llama3.2".to_string(),
            api_key: None,
            base_url: Some("http://custom:11434".to_string()),
        };
        let result = create_provider(&config, MetricsTracker::new());
        assert!(result.is_ok());
    }
}
